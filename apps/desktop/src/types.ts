export interface Device {
  id: string;
  name: string;
  adapter: string;
  near_rssi: number;
  far_rssi: number;
  /** Seamless unlock: a far-then-near return unlocks at once; off waits for keyboard or mouse input. */
  auto_unlock_on_return: boolean;
  enabled: boolean;
  identity_configured: boolean;
  /** Windows identity address once bound through the paired-device flow. */
  address?: string | null;
  /** Seconds a far-then-near return waits for the logon UI (5–120). */
  return_window_seconds?: number;
}

/** A device Windows has paired over Bluetooth LE. Public metadata only. */
export interface PairedDevice {
  name: string | null;
  address: string;
  bound: boolean;
}

export interface Notifications {
  endpoint: string;
  configured: boolean;
  enabled: boolean;
  /** Push a notice after an unlock this app submitted. Defaults to on. */
  notify_on_unlock?: boolean;
}

export interface HistoryEntry {
  at_ms: number;
  event: string;
  device_id?: string | null;
  detail: string;
}

export interface Snapshot {
  devices: Device[];
  notifications: Notifications;
  /** Absent from backends older than this setting. */
  settings?: { scan_with_lid_closed: boolean };
  credential_configured: boolean;
  history: HistoryEntry[];
  backend_running: boolean;
  runtime: BackendRuntime;
}

export interface BackendRuntime {
  running: boolean;
  at_ms?: number;
  locked?: boolean;
  provider_ready?: boolean;
  scanner_active?: boolean;
  submitted_this_lock?: boolean;
  devices?: {
    id: string;
    rssi: number | null;
    /** Last signal however old; `rssi` is only set while it is under 2 seconds old. */
    last_rssi?: number | null;
    last_seen_ms?: number | null;
    presence: string;
    armed: boolean;
    wearer_state: "unknown";
  }[];
}

export interface Signal {
  rssi: number;
  samples: number[];
  lastSeen: number;
  /** How old the shown value is; 0 or absent while the signal is live. */
  ageMs?: number;
}

export interface DeviceSignal extends Signal {
  deviceId: string;
}

export interface Advertisement {
  address: string;
  name: string | null;
  rssi: number;
  apple: boolean;
  matched_device_id: string | null;
  matched_name?: string | null;
}

export interface ObservedDevice extends Advertisement {
  samples: number[];
  lastSeen: number;
}

export interface RuntimeStatus {
  backend_available: boolean;
  daemon_running: boolean;
}

export interface PairingStatus {
  event: "pairing_window";
  status: "started" | "waiting" | "stopped";
  paired: boolean;
  irk_verified: boolean;
  watch_identity_verified: boolean;
  remaining_seconds: number;
  advertising: string;
  subscriptions: number;
  encrypted_reads: number;
  reason: string;
}
export type Page =
  "overview" | "devices" | "history" | "notifications";

export const emptySnapshot = (): Snapshot => ({
  devices: [],
  notifications: {
    endpoint: "https://api.day.app/push",
    configured: false,
    enabled: false,
  },
  credential_configured: false,
  backend_running: false,
  runtime: { running: false },
  history: [],
});

/** Whether this window is the installed copy, and its login component and autostart state. */
export interface SetupStatus {
  running_installed: boolean;
  provider_registered: boolean;
  autostart: boolean;
}
