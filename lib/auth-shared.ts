import { env } from 'cloudflare:workers';

export const encoder = new TextEncoder();
export const SESSION_SECONDS = 7 * 24 * 60 * 60;
export const json = (value: unknown, status = 200, extra: Record<string, string> = {}) => Response.json(value, {
  status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', ...extra },
});
export const randomToken = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const hash = async (value: string) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)))].map(b => b.toString(16).padStart(2, '0')).join('');
export const sameOrigin = (r: Request) => r.headers.get('origin') === new URL(r.url).origin && r.headers.get('sec-fetch-site') !== 'cross-site';
export function cookieName(r: Request, suffix = '') { return (new URL(r.url).protocol === 'https:' ? '__Host-shadowgraph' : 'shadowgraph_local') + suffix; }
export function readCookie(r: Request, name: string) { return (r.headers.get('cookie') || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))?.slice(name.length + 1); }
export function authCookie(r: Request, value: string, age = SESSION_SECONDS, suffix = '', sameSite: 'Strict' | 'Lax' = 'Strict') {
  return `${cookieName(r, suffix)}=${value}; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=${age}${new URL(r.url).protocol === 'https:' ? '; Secure' : ''}`;
}
export const nameKey = (s: string) => s.normalize('NFKC').trim().toLocaleLowerCase('ru-RU').replace(/\s+/g, '_').replace(/[аеорсхуктвмн]/g, c => ({ 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'к': 'k', 'т': 't', 'в': 'b', 'м': 'm', 'н': 'h' }[c] || c));
export type Account = { id: string; name: string; owner: string; createdAt: number; role: 'owner' | 'member'; vaultKey: string };
export const visibleAccount = (a: Account) => ({ id: a.id, name: a.name, createdAt: a.createdAt, role: a.role });

export async function initializeAccounts() {
  const setting = await env.DB!.prepare("SELECT value FROM sg_settings WHERE key='owner_account_id'").first<{ value: string }>();
  if (!setting) {
    const first = await env.DB!.prepare('SELECT id FROM sg_accounts ORDER BY created_at,id LIMIT 1').first<{ id: string }>();
    await env.DB!.prepare("INSERT OR IGNORE INTO sg_settings(key,value) VALUES('owner_account_id',?)").bind(first?.id || 'unconfigured').run();
  }
  await env.DB!.prepare("UPDATE sg_accounts SET role='owner' WHERE id=(SELECT value FROM sg_settings WHERE key='owner_account_id') AND role<>'owner'").run();
  const old = await env.DB!.prepare('SELECT id,name FROM sg_accounts WHERE name_key IS NULL').all<{ id: string; name: string }>();
  for (const a of old.results) {
    try { await env.DB!.prepare('UPDATE sg_accounts SET name_key=? WHERE id=? AND name_key IS NULL').bind(nameKey(a.name), a.id).run(); }
    catch { await env.DB!.prepare('UPDATE sg_accounts SET name_key=? WHERE id=? AND name_key IS NULL').bind(nameKey(a.name) + ':legacy:' + a.id, a.id).run(); }
  }
}
async function ensureVault(a: Account) {
  if (!a.vaultKey) {
    await env.DB!.prepare('UPDATE sg_accounts SET vault_key=? WHERE id=? AND vault_key IS NULL').bind(randomToken(), a.id).run();
    a.vaultKey = (await env.DB!.prepare('SELECT vault_key AS k FROM sg_accounts WHERE id=?').bind(a.id).first<{ k: string }>())!.k;
  }
  return a;
}
export async function getAccount(r: Request): Promise<Account | null> {
  const secret = readCookie(r, cookieName(r));
  if (!env.DB || !secret || !/^[-\w]{43}$/.test(secret)) return null;
  await initializeAccounts();
  // The session and account are resolved exclusively from server records. Platform headers and client IDs confer no access.
  const row = await env.DB.prepare('SELECT a.id,a.owner,a.name,a.created_at AS createdAt,a.role,a.vault_key AS vaultKey FROM sg_sessions s JOIN sg_accounts a ON a.id=s.account_id AND a.owner=s.owner WHERE s.token_hash=? AND s.expires_at>?').bind(await hash(secret), Date.now()).first<Account>();
  return row ? ensureVault(row) : null;
}
export async function sessionSuccess(r: Request, id: string, status = 200, extra: Record<string, unknown> = {}) {
  const row = await env.DB!.prepare('SELECT id,owner,name,role,created_at AS createdAt,vault_key AS vaultKey FROM sg_accounts WHERE id=?').bind(id).first<Account>();
  if (!row) throw Error('Account missing');
  const account = await ensureVault(row), secret = randomToken(), old = readCookie(r, cookieName(r));
  const statements = [env.DB!.prepare('INSERT INTO sg_sessions(token_hash,account_id,owner,expires_at) VALUES(?,?,?,?)').bind(await hash(secret), id, account.owner, Date.now() + SESSION_SECONDS * 1000)];
  if (old && /^[-\w]{43}$/.test(old)) statements.push(env.DB!.prepare('DELETE FROM sg_sessions WHERE token_hash=?').bind(await hash(old)));
  await env.DB!.batch(statements);
  return json({ account: visibleAccount(account), vaultKey: account.vaultKey, ...extra }, status, { 'Set-Cookie': authCookie(r, secret) });
}
export async function authRate(scope: string, identity: string, duration: number, max: number) {
  const row = await env.DB!.prepare('INSERT INTO sg_auth_attempts(id,count,expires_at) VALUES(?,1,?) ON CONFLICT(id) DO UPDATE SET count=count+1 RETURNING count').bind(`${scope}:${identity}:${Math.floor(Date.now() / duration)}`, Date.now() + duration * 2).first<{ count: number }>();
  return !!row && row.count <= max;
}
export const requestIdentity = async (r: Request) => hash(r.headers.get('cf-connecting-ip') || 'anonymous');
export async function readSmallJson(r: Request) {
  if (Number(r.headers.get('content-length') || 0) > 4096) throw Error('body_limit');
  const reader = r.body?.getReader();
  if (!reader) throw Error('body');
  const parts: Uint8Array[] = []; let size = 0;
  try {
    for (;;) { const chunk = await reader.read(); if (chunk.done) break; size += chunk.value.length; if (size > 4096) { await reader.cancel(); throw Error('body_limit'); } parts.push(chunk.value); }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0; for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  const body = JSON.parse(new TextDecoder().decode(bytes));
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw Error('body');
  return body;
}
