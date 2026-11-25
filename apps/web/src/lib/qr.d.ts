/** Types for qr.mjs (a QR code made in the page, copied from CxMissionZero's public/qr.js). */
export const QR_MAX_VERSION: number;
export const QR_MAX_BYTES: number;
export function qrMatrix(text: string, options?: { mask?: number | null }): { version: number; size: number; mask: number; modules: boolean[][] };
export function qrSvgPath(text: string, options?: { quiet?: number }): { side: number; viewBox: string; d: string };
