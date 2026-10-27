import { escape } from "./render";
import type { Device } from "./types";

export function openDeviceDialog(
  device?: Device,
  suggestedName?: string | null,
): HTMLDialogElement {
  const dialog = document.querySelector<HTMLDialogElement>("#device-dialog")!;
  dialog.innerHTML = `<form id="device-form"><div class="dialog-heading"><div><div class="eyebrow">APPLE BLE ADAPTER</div><h2 id="device-dialog-title">${device ? "配置设备" : "绑定已配对设备"}</h2></div><button type="button" class="close-button" id="close-dialog" aria-label="关闭对话框">×</button></div>
    <input type="hidden" name="id" value="${escape(device?.id || "")}"/>
    <label>设备显示名称<input name="name" required maxlength="80" value="${escape(device?.name || suggestedName || "")}" placeholder="例如：我的 Apple Watch"/></label>
    ${device?.identity_configured
      // Binding already stored the identity: nothing about it is left for the user to fill in.
      ? '<p class="saved-secret">✓ 手表身份已在绑定时自动保存，这里只需要调整下面的设置。</p>'
      : identityFields()}
    <div class="form-grid"><label>靠近阈值 · dBm<input name="near_rssi" type="number" min="-100" max="-20" step="1" required value="${device?.near_rssi ?? -60}"/></label><label>远离阈值 · dBm<input name="far_rssi" type="number" min="-110" max="-25" step="1" required value="${device?.far_rssi ?? -72}"/></label></div>
    <p class="form-hint">数值越接近 0，信号越强。远离阈值应低于靠近阈值，避免边界来回切换。</p>
    <label>返回后等待解锁界面 · 秒<input name="return_window_seconds" type="number" min="5" max="120" step="1" required value="${device?.return_window_seconds ?? 30}"/><small>走远再回来后，在这段时间内打开解锁界面且手表仍在近处，就会立即解锁。只影响判断时长，不增加扫描频率或耗电。</small></label>
    <label class="toggle-row"><input name="enabled" type="checkbox" ${device?.enabled === false ? "" : "checked"}/><span><strong>启用此设备</strong><small>停用后保留身份与配置。</small></span></label>
    <label class="toggle-row"><input name="auto_unlock_on_return" type="checkbox" ${device?.auto_unlock_on_return === false ? "" : "checked"}/><span><strong>无感解锁</strong><small>开启：锁屏后走远再回来，靠近即自动解锁。关闭：回来后需要动一下键盘或鼠标才解锁。一直待在电脑旁的锁屏不会自动解锁；无法检测手表是否锁定或佩戴。</small></span></label>
    <div class="form-actions">${device ? '<button type="button" class="text-button danger" id="remove-device">移除设备</button>' : ""}<span class="spacer"></span><button class="button secondary" id="cancel-dialog" type="button">取消</button><button class="button primary" type="submit">保存设备</button></div></form>`;
  dialog.showModal();
  const source = dialog.querySelector<HTMLSelectElement>('[name="identity_source"]');
  if (source) source.onchange = (event) => {
    const file = (event.target as HTMLSelectElement).value === "file";
    const irk = dialog.querySelector<HTMLInputElement>('[name="irk"]')!;
    const path = dialog.querySelector<HTMLInputElement>('[name="irk_blob_path"]')!;
    // Switching source discards the inactive secret instead of retaining both.
    irk.value = "";
    path.value = "";
    irk.disabled = file;
    path.disabled = !file;
    irk.required = !file;
    path.required = file;
    dialog.querySelector<HTMLElement>("#irk-field")!.hidden = file;
    dialog.querySelector<HTMLElement>("#identity-file-field")!.hidden = !file;
  };
  dialog.querySelector<HTMLButtonElement>("#close-dialog")!.onclick = () =>
    dialog.close();
  dialog.querySelector<HTMLButtonElement>("#cancel-dialog")!.onclick = () =>
    dialog.close();
  dialog.addEventListener(
    "close",
    () => {
      dialog
        .querySelectorAll<HTMLInputElement>('input[type="password"]')
        .forEach((input) => {
          input.value = "";
        });
    },
    { once: true },
  );
  return dialog;
}

/** Manual identity entry, only for a device that has none yet (normally binding fills it in). */
function identityFields(): string {
  return `<p class="form-hint">一般不用手动登记：在「设备」页的「添加手表」里配对并点「绑定此设备」，身份会自动保存。只有已经自己取得这块手表的 IRK 时，才在这里填写。</p>
    <label>身份导入方式<select name="identity_source"><option value="manual">手动输入 IRK</option><option value="file">CurrentUser DPAPI 密文文件</option></select></label>
    <label id="irk-field">手表 IRK<input name="irk" type="password" autocomplete="new-password" pattern="[0-9a-fA-F]{32}" maxlength="32" required placeholder="32 位十六进制身份密钥"/></label>
    <label id="identity-file-field" hidden>身份密文文件绝对路径<input name="irk_blob_path" type="password" autocomplete="new-password" maxlength="4096" disabled placeholder="粘贴 .dpapi 或 .blob 文件的完整路径"/><small>文件必须由当前 Windows 账户加密，解密后恰好为 16 字节。路径仅用于本次导入，不写入设备配置或日志。</small></label>`;
}

export function secretFields(form: HTMLFormElement): void {
  form
    .querySelectorAll<HTMLInputElement>('input[type="password"]')
    .forEach((input) => {
      input.value = "";
    });
}

export function field(form: FormData, name: string): string {
  return String(form.get(name) || "").trim();
}
