import { backendLabel, deviceCard, historyTable, readinessHtml, signalValue, sparkline } from "./render";
import type {
  DeviceSignal,
  ObservedDevice,
  Page,
  RuntimeStatus,
  Snapshot,
} from "./types";

export function collectSignals(
  next: Snapshot,
  previous: DeviceSignal[],
  observed: ObservedDevice[],
): DeviceSignal[] {
  if (!next.backend_running)
    return observed
      .filter((o) => o.matched_device_id)
      .map((o) => ({
        deviceId: o.matched_device_id!,
        rssi: o.rssi,
        samples: o.samples,
        lastSeen: o.lastSeen,
      }));
  return (next.runtime.devices || [])
    .filter((d) => d.rssi !== null || d.last_rssi != null)
    .map((device) => {
      const prior = previous.find((s) => s.deviceId === device.id);
      const at = next.runtime.at_ms || Date.now();
      const live = device.rssi !== null;
      const rssi = live ? device.rssi! : device.last_rssi!;
      const ageMs = live ? 0 : device.last_seen_ms ?? 0;
      return {
        deviceId: device.id,
        rssi,
        lastSeen: at - ageMs,
        ageMs,
        // Only live readings extend the chart; a stale value is the same old sample.
        samples:
          !live || prior?.lastSeen === at
            ? prior?.samples || []
            : [...(prior?.samples || []), rssi].slice(-30),
      };
    });
}

export function patchLive(
  data: Snapshot,
  status: RuntimeStatus,
  signals: DeviceSignal[],
  page: Page,
  onEdit: (id?: string) => void,
  onRemove: (id: string) => void,
): void {
  const button = document.querySelector<HTMLButtonElement>("#daemon-toggle");
  const label = backendLabel(data, status);
  if (button) {
    button.textContent = label.action;
    button.disabled = label.disabled;
  }
  const note = document.querySelector<HTMLElement>(".hero-note");
  if (note) note.textContent = label.note;
  const state = document.querySelector<HTMLElement>("#backend-state");
  if (state)
    state.textContent = data.backend_running ? "后台心跳正常" : "后台尚未就绪";
  const hasIdentity = data.devices.some((device) => device.identity_configured);
  const password = document.querySelector<HTMLInputElement>("#windows-password");
  const savePassword = document.querySelector<HTMLButtonElement>("#save-credential");
  const requirement = document.querySelector<HTMLElement>("#credential-requirement");
  if (password) password.disabled = !hasIdentity;
  if (savePassword) savePassword.disabled = !hasIdentity;
  if (requirement) requirement.textContent = hasIdentity
    ? "设备身份已绑定，可以设置当前账户密码。"
    : "请先绑定设备身份，再设置当前账户密码。";
  const cards = document.querySelector<HTMLElement>(".device-grid");
  if (cards && !cards.contains(document.activeElement)) {
    const devices =
      page === "overview" ? data.devices.slice(0, 3) : data.devices;
    if (cards.querySelectorAll(".device-card").length !== devices.length) {
      cards.innerHTML = devices
        .map((d) =>
          deviceCard(
            d,
            data,
            signals.find((s) => s.deviceId === d.id),
          ),
        )
        .join("");
      cards.querySelectorAll<HTMLButtonElement>("[data-edit]").forEach((b) => {
        b.onclick = () => onEdit(b.dataset.edit);
      });
      cards.querySelectorAll<HTMLButtonElement>("[data-remove]").forEach((b) => {
        b.onclick = () => onRemove(b.dataset.remove || "");
      });
    } else {
      cards
        .querySelectorAll<HTMLElement>("[data-device-id]")
        .forEach((card) => {
          const signal = signals.find(
            (s) => s.deviceId === card.dataset.deviceId,
          );
          const device = data.devices.find((d) => d.id === card.dataset.deviceId);
          const ready = card.querySelector<HTMLElement>(".card-ready");
          if (device && ready) ready.innerHTML = readinessHtml(device, data, signal);
          const value = card.querySelector<HTMLElement>(".signal-value");
          const chart = card.querySelector<HTMLElement>(".signal-chart");
          if (value) value.innerHTML = signalValue(signal);
          if (chart) chart.innerHTML = sparkline(signal?.samples || []);
        });
    }
  }
  const history = document.querySelector<HTMLElement>("#activity-content");
  if (history)
    history.innerHTML = historyTable(
      data.history,
      data.devices,
      page === "overview" ? 5 : data.history.length,
    );
}
