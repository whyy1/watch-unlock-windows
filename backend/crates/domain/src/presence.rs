use serde::{Deserialize, Serialize};
use std::fmt;

/// Hysteresis thresholds, expressed in BLE RSSI dBm.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DevicePolicy {
    pub near_rssi: i16,
    pub far_rssi: i16,
}

impl DevicePolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if !valid_rssi(self.near_rssi) || !valid_rssi(self.far_rssi) {
            return Err(PolicyError::InvalidRssi);
        }
        if self.far_rssi >= self.near_rssi {
            return Err(PolicyError::InvalidThresholds);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum Presence {
    #[default]
    Unknown,
    Near,
    Away,
}

/// Generation must increase whenever a new Windows lock session begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Session {
    pub generation: u64,
    pub locked: bool,
}

/// Use one monotonic clock origin for every observation in a process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    Signal { rssi: i16, at_ms: u64 },
    /// Explicit adapter failure/rebuild, not ordinary silence from a distant device.
    Unavailable { at_ms: u64 },
    Suspended { at_ms: u64 },
    Wake { at_ms: u64 },
}

impl Observation {
    fn at_ms(self) -> u64 {
        match self {
            Self::Signal { at_ms, .. }
            | Self::Unavailable { at_ms }
            | Self::Suspended { at_ms }
            | Self::Wake { at_ms } => at_ms,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Decision {
    #[default]
    None,
    ReturnUnlock,
}

/// Never persist this state across process restart or share it between devices.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceState {
    generation: u64,
    locked: bool,
    presence: Presence,
    armed: bool,
    return_emitted: bool,
    last_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    pub state: DeviceState,
    pub decision: Decision,
}

impl DeviceState {
    pub fn presence(&self) -> Presence {
        self.presence
    }

    pub fn armed(&self) -> bool {
        self.armed
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// An arrival that never reached the credential provider is not an attempt.
    /// Expiring it revokes the distance evidence; only a subsequently observed far
    /// crossing can authorize again. Never call after submission.
    pub fn expire_unsubmitted_return(&self) -> Self {
        if !self.return_emitted {
            return self.clone();
        }
        Self {
            generation: self.generation,
            locked: self.locked,
            last_at_ms: self.last_at_ms,
            ..Self::default()
        }
    }

    /// Carries a far crossing observed just before this lock into the lock cycle, for locks
    /// that only happen once the watch is already gone (Windows Dynamic Lock). The caller
    /// must only pass evidence from a scanner that stayed healthy up to the lock.
    pub fn arm_departed(&self) -> Self {
        if !self.locked || self.return_emitted {
            return self.clone();
        }
        Self { presence: Presence::Away, armed: true, ..self.clone() }
    }

    /// Returns a new state; an error leaves the caller's state unchanged.
    /// Explicit adapter loss, recovery wake and suspend revoke automatic authority.
    /// Ordinary device silence sends no observation: it cannot arm an unknown device,
    /// and does not revoke an already observed far crossing on a healthy adapter.
    pub fn step(
        &self,
        policy: &DevicePolicy,
        session: Session,
        observation: Observation,
    ) -> Result<Transition, PolicyError> {
        policy.validate()?;
        if session.generation < self.generation {
            return Err(PolicyError::GenerationWentBackwards);
        }
        let at_ms = observation.at_ms();
        if self.last_at_ms.is_some_and(|previous| at_ms < previous) {
            return Err(PolicyError::ClockWentBackwards);
        }
        if let Observation::Signal { rssi, .. } = observation {
            if !valid_rssi(rssi) {
                return Err(PolicyError::InvalidRssi);
            }
        }
        let reset = session.generation != self.generation || session.locked != self.locked;
        let base = if reset {
            Self {
                generation: session.generation,
                locked: session.locked,
                ..Self::default()
            }
        } else {
            self.clone()
        };
        let current = Self { last_at_ms: Some(at_ms), ..base };
        if !session.locked {
            return Ok(Transition {
                state: Self {
                    presence: Presence::Unknown,
                    armed: false,
                    return_emitted: false,
                    ..current
                },
                decision: Decision::None,
            });
        }
        match observation {
            Observation::Signal { rssi, .. } => current.signal(policy, rssi),
            Observation::Unavailable { .. }
            | Observation::Suspended { .. }
            | Observation::Wake { .. } => Ok(Transition {
                state: Self { presence: Presence::Unknown, armed: false, ..current },
                decision: Decision::None,
            }),
        }
    }

    fn signal(self, policy: &DevicePolicy, rssi: i16) -> Result<Transition, PolicyError> {
        if rssi <= policy.far_rssi {
            return Ok(Transition {
                state: Self {
                    presence: Presence::Away,
                    armed: !self.return_emitted,
                    ..self
                },
                decision: Decision::None,
            });
        }
        if rssi < policy.near_rssi {
            return Ok(Transition { state: self, decision: Decision::None });
        }
        if self.armed && !self.return_emitted {
            return Ok(Transition {
                state: Self {
                    presence: Presence::Near,
                    armed: false,
                    return_emitted: true,
                    ..self
                },
                decision: Decision::ReturnUnlock,
            });
        }
        // Near without an observed far crossing in this lock cycle never authorizes.
        Ok(Transition {
            state: Self { presence: Presence::Near, armed: false, ..self },
            decision: Decision::None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    InvalidRssi,
    InvalidThresholds,
    ClockWentBackwards,
    GenerationWentBackwards,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRssi => "RSSI must be between -127 and 20 dBm",
            Self::InvalidThresholds => "far RSSI must be lower than near RSSI",
            Self::ClockWentBackwards => "observation clock went backwards",
            Self::GenerationWentBackwards => "session generation went backwards",
        })
    }
}

impl std::error::Error for PolicyError {}

fn valid_rssi(rssi: i16) -> bool {
    (-127..=20).contains(&rssi)
}
