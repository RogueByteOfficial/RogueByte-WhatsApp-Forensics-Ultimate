/**
 * RogueByte WhatsApp Forensics Ultimate - Cryptographic Utilities
 */

export async function calculateSha256(data: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

export function formatUtcToLocal(utcStr: string): string {
  if (!utcStr || utcStr.startsWith('UNKNOWN')) return utcStr;
  try {
    const cleanStr = utcStr.replace(' UTC', 'Z').replace(' ', 'T');
    const date = new Date(cleanStr);
    if (isNaN(date.getTime())) return utcStr;
    return date.toLocaleString();
  } catch {
    return utcStr;
  }
}

export function epochMsToUtc(ms: number): string {
  if (!ms || ms <= 0) return 'UNKNOWN_TIMESTAMP';
  try {
    const d = new Date(ms);
    return d.toISOString().replace('T', ' ').replace('Z', ' UTC');
  } catch {
    return `INVALID_EPOCH(${ms})`;
  }
}

export function formatHexOffset(offset?: number): string {
  if (offset === undefined || offset === null) return 'N/A';
  return '0x' + offset.toString(16).toUpperCase().padStart(8, '0');
}
