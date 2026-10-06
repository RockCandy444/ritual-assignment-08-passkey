export class AppError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}
export function json(value: unknown, status = 200, headers = new Headers()) {
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Vary', 'Cookie');
  return new Response(JSON.stringify(value), {status, headers});
}
export function token() { return toBase64(crypto.getRandomValues(new Uint8Array(32))); }
export function toBase64(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
export function fromBase64(text: string) {
  return Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
}
export async function hash(value: string) {
  return toBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
}
export function cookieName(req: Request, suffix: string) {
  return (new URL(req.url).protocol === 'https:' ? '__Host-' : '') + 't08_' + suffix;
}
export function readCookie(req: Request, suffix: string) {
  const name = cookieName(req, suffix);
  const value = (req.headers.get('Cookie') || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))?.slice(name.length + 1);
  return value && /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}
export function setCookie(headers: Headers, req: Request, suffix: string, value: string, maxAge: number) {
  headers.append('Set-Cookie', `${cookieName(req, suffix)}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${new URL(req.url).protocol === 'https:' ? '; Secure' : ''}`);
}
export function requireSameOrigin(req: Request) {
  const url = new URL(req.url);
  if (req.headers.get('Origin') !== url.origin) throw new AppError(403, 'ORIGIN_DENIED', '다른 사이트에서 보낸 요청은 처리할 수 없어요.');
  if (req.headers.get('Sec-Fetch-Site') === 'cross-site') throw new AppError(403, 'ORIGIN_DENIED', '다른 사이트의 요청은 처리할 수 없어요.');
  if (!req.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')) throw new AppError(415, 'JSON_REQUIRED', '요청 형식을 확인해 주세요.');
}
export async function body(req: Request): Promise<Record<string, unknown>> {
  if (Number(req.headers.get('Content-Length') || 0) > 32768) throw new AppError(413, 'BODY_TOO_LARGE', '요청이 너무 커요.');
  // Bound chunked requests too, before parsing JSON.
  const reader = req.body?.getReader();
  if (!reader) throw new AppError(400, 'INVALID_JSON', '요청 내용을 확인해 주세요.');
  let size = 0; const parts: Uint8Array[] = [];
  while (true) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength;
    if (size > 32768) { await reader.cancel(); throw new AppError(413, 'BODY_TOO_LARGE', '요청이 너무 커요.'); } parts.push(part.value); }
  const all = new Uint8Array(size); let offset = 0; for (const part of parts) { all.set(part, offset); offset += part.length; }
  try { const value = JSON.parse(new TextDecoder().decode(all)); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(); return value; }
  catch { throw new AppError(400, 'INVALID_JSON', '요청 내용을 확인해 주세요.'); }
}
export function field(value: unknown, label: string, max = 50) {
  if (typeof value !== 'string' || value.trim().length < 1 || value.trim().length > max || /[\u0000-\u001f<>]/.test(value))
    throw new AppError(400, 'INVALID_FIELD', `${label}을 확인해 주세요.`);
  return value.trim();
}
