const byteLength = (value: string): number => new TextEncoder().encode(value).length;
const controls = /[\u0000-\u001f\u007f-\u009f]/;

export function validateDevice(
  name: string, near: number, far: number, irk: string, path: string,
  existingIdentity: boolean,
): void {
  if (!name || byteLength(name) > 240 || controls.test(name))
    throw new Error("设备名称不能为空，且不能超过 240 字节或包含控制字符。");
  if (!Number.isInteger(near) || near < -100 || near > -20 ||
      !Number.isInteger(far) || far < -110 || far > -25 || far >= near)
    throw new Error("靠近阈值应在 -100 至 -20 dBm，远离阈值应在 -110 至 -25 dBm，且低于靠近阈值。");
  if (irk && !/^[0-9a-fA-F]{32}$/.test(irk))
    throw new Error("IRK 必须为 32 位十六进制。");
  if (path && (byteLength(path) > 4096 || controls.test(path) ||
      !/^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+\\).+\.(?:dpapi|blob)$/i.test(path)))
    throw new Error("请选择 .dpapi 或 .blob 密文文件的 Windows 绝对路径。");
  if ((irk && path) || (!irk && !path && !existingIdentity))
    throw new Error("请选择一种身份导入方式：手动 IRK 或当前 Windows 账户加密的密文文件。");
}

export function validatePassword(password: string, hasIdentity: boolean): void {
  if (!hasIdentity) throw new Error("请先绑定设备身份，再设置 Windows 账户密码。");
  if (!password || byteLength(password) > 1024 || password.includes("\0"))
    throw new Error("请输入有效的 Windows 账户密码，长度不能超过 1024 字节。");
}

function validateWebUrl(value: string): void {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error("请输入完整的地址，以 http:// 或 https:// 开头。"); }
  const scheme = /^https?:\/\//i.exec(value);
  const authority = value.slice(scheme ? scheme[0].length : 0).split(/[/?]/, 1)[0];
  if (!scheme || byteLength(value) > 2048 ||
      /[\s\\#]/u.test(value) || controls.test(value) || /[%@]/.test(authority) ||
      (url.protocol !== "https:" && url.protocol !== "http:") || !url.hostname || url.username || url.password)
    throw new Error("通知地址要以 http:// 或 https:// 开头，不能带账户信息、# 片段或空格。");
}

export function validateNotifications(endpoint: string, barkKey: string, keySaved: boolean): void {
  if (!endpoint.trim()) throw new Error("请填写推送 API 地址。");
  if (!barkKey && !keySaved) throw new Error("请填写 Bark 设备密钥。");
  validateWebUrl(endpoint);
  // The usual mistake is pasting the whole sample URL from the Bark app instead of its key.
  if (barkKey && /[/:.]/.test(barkKey))
    throw new Error("只填 Bark 网址中域名后面的那一段密钥，不要填整个网址。例如 https://api.day.app/YourKey123/推送内容 里填 YourKey123。");
  if (barkKey && !/^[A-Za-z0-9_-]{8,256}$/.test(barkKey))
    throw new Error("Bark 密钥应为 8 至 256 位字母、数字、下划线或连字符，不含空格。");
}
