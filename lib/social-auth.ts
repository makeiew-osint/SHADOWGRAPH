import { env } from 'cloudflare:workers';
import { authCookie, authRate, cookieName, encoder, hash, randomToken, readCookie, requestIdentity, sessionSuccess } from './auth-shared';

type Provider = 'google' | 'telegram' | 'github';
type Pending = { provider: Provider; subject: string; name: string };
const FLOW_SECONDS = 600;
const definitions = {
  google: { authorize: 'https://accounts.google.com/o/oauth2/v2/auth', token: 'https://oauth2.googleapis.com/token', jwks: 'https://www.googleapis.com/oauth2/v3/certs', issuers: ['https://accounts.google.com', 'accounts.google.com'], scope: 'openid profile' },
  telegram: { authorize: 'https://oauth.telegram.org/auth', token: 'https://oauth.telegram.org/token', jwks: 'https://oauth.telegram.org/.well-known/jwks.json', issuers: ['https://oauth.telegram.org'], scope: 'openid profile' },
  github: { authorize: 'https://github.com/login/oauth/authorize', token: 'https://github.com/login/oauth/access_token', jwks: '', issuers: [], scope: 'read:user' },
} as const;
function providerConfig(provider: Provider) {
  const values = env as unknown as Record<string, unknown>, prefix = provider.toUpperCase();
  const clientId = values[prefix + '_CLIENT_ID'], clientSecret = values[prefix + '_CLIENT_SECRET'];
  return typeof clientId === 'string' && clientId.trim() && typeof clientSecret === 'string' && clientSecret.trim() ? { clientId: clientId.trim(), clientSecret: clientSecret.trim() } : null;
}
export function providerStatus() { return { key: true, google: !!providerConfig('google'), telegram: !!providerConfig('telegram'), github: !!providerConfig('github') }; }
function parseProvider(value: string): Provider | null { return value === 'google' || value === 'telegram' || value === 'github' ? value : null; }
function redirect(r: Request, path: string, cookies: string[] = []) {
  const headers = new Headers({ Location: new URL(path, r.url).href, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' });
  for (const value of cookies) headers.append('Set-Cookie', value);
  return new Response(null, { status: 303, headers });
}
function failure(r: Request, code: string, provider?: Provider) { return redirect(r, '/workspace?auth_error=' + encodeURIComponent(code) + (provider ? '&provider=' + provider : ''), [authCookie(r, '', 0, '_oauth', 'Lax')]); }
export const clearPendingCookie = (r: Request) => authCookie(r, '', 0, '_pending');
export async function pendingIdentity(r: Request): Promise<Pending | null> {
  const secret = readCookie(r, cookieName(r, '_pending'));
  if (!env.DB || !secret || !/^[-\w]{43}$/.test(secret)) return null;
  return env.DB.prepare('SELECT provider,subject,name FROM sg_oauth_pending WHERE token_hash=? AND expires_at>?').bind(await hash(secret), Date.now()).first<Pending>();
}
export async function attachPendingIdentity(r: Request, accountId: string) {
  const secret = readCookie(r, cookieName(r, '_pending'));
  if (!secret || !/^[-\w]{43}$/.test(secret)) return null;
  const identity = await env.DB!.prepare('DELETE FROM sg_oauth_pending WHERE token_hash=? AND expires_at>? RETURNING provider,subject,name').bind(await hash(secret), Date.now()).first<Pending>();
  if (!identity) return null;
  await env.DB!.prepare('INSERT OR IGNORE INTO sg_identities(provider,subject,account_id,created_at) VALUES(?,?,?,?)').bind(identity.provider, identity.subject, accountId, Date.now()).run();
  const linked = await env.DB!.prepare('SELECT account_id AS accountId FROM sg_identities WHERE provider=? AND subject=?').bind(identity.provider, identity.subject).first<{ accountId: string }>();
  return { provider: identity.provider, linked: linked?.accountId === accountId };
}
const base64Url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const decode = (s: string) => { if (!/^[A-Za-z0-9_-]+$/.test(s)) throw Error('token_encoding'); return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); };
async function fetchJson(url: string, init: RequestInit = {}) {
  const response = await fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw Error('provider_request');
  const reader = response.body?.getReader(); if (!reader) throw Error('provider_body');
  const chunks: Uint8Array[] = []; let length = 0;
  try { for (;;) { const part = await reader.read(); if (part.done) break; length += part.value.length; if (length > 131072) { await reader.cancel(); throw Error('provider_body_limit'); } chunks.push(part.value); } } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder().decode(bytes));
}
// Only fixed provider JWKS URLs are fetched. Token-controlled jku/x5u URLs and unsigned/symmetric algorithms are never used.
export async function verifyIdentityToken(provider: 'google' | 'telegram', jwt: string, clientId: string, nonce: string): Promise<Pending> {
  if (typeof jwt !== 'string' || jwt.length > 20000) throw Error('token_size');
  const parts = jwt.split('.'); if (parts.length !== 3) throw Error('token_format');
  const header = JSON.parse(new TextDecoder().decode(decode(parts[0])));
  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || header.crit) throw Error('token_algorithm');
  const keySet = await fetchJson(definitions[provider].jwks);
  const jwk = Array.isArray(keySet.keys) ? keySet.keys.find((k: JsonWebKey & { kid?: string }) => k.kid === header.kid && k.kty === 'RSA' && (!k.use || k.use === 'sig') && (!k.alg || k.alg === 'RS256')) : null;
  if (!jwk) throw Error('token_key');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, decode(parts[2]), encoder.encode(parts[0] + '.' + parts[1]))) throw Error('token_signature');
  const c = JSON.parse(new TextDecoder().decode(decode(parts[1]))), now = Math.floor(Date.now() / 1000);
  const audience = Array.isArray(c.aud) ? c.aud.includes(clientId) && (c.aud.length === 1 || c.azp === clientId) : c.aud === clientId;
  if (!(definitions[provider].issuers as readonly string[]).includes(c.iss) || !audience || (c.azp !== undefined && c.azp !== clientId) || c.nonce !== nonce || typeof c.exp !== 'number' || c.exp <= now || typeof c.iat !== 'number' || c.iat > now + 60 || c.iat < now - 3600 || (c.nbf !== undefined && (typeof c.nbf !== 'number' || c.nbf > now + 60)) || typeof c.sub !== 'string' || !c.sub || c.sub.length > 255) throw Error('token_claims');
  return { provider, subject: c.sub, name: typeof c.name === 'string' ? c.name.slice(0, 100) : typeof c.preferred_username === 'string' ? c.preferred_username.slice(0, 100) : provider };
}
export async function startProvider(r: Request, value: string) {
  const provider = parseProvider(value);
  if (!provider) return failure(r, 'provider_unknown');
  const config = providerConfig(provider);
  if (!config) return failure(r, 'provider_unavailable', provider);
  if (!env.DB) return failure(r, 'auth_unavailable', provider);
  if (r.headers.get('sec-fetch-site') === 'cross-site') return failure(r, 'flow_invalid', provider);
  if (!await authRate('oauth_start', await requestIdentity(r), 60000, 15)) return failure(r, 'rate_limit', provider);
  await env.DB.batch([env.DB.prepare('DELETE FROM sg_oauth_states WHERE expires_at<?').bind(Date.now()), env.DB.prepare('DELETE FROM sg_oauth_pending WHERE expires_at<?').bind(Date.now())]);
  const state = randomToken(), binding = randomToken(), verifier = randomToken(), nonce = randomToken();
  const redirectUri = new URL('/api/auth/provider/' + provider + '/callback', r.url).href;
  await env.DB.prepare('INSERT INTO sg_oauth_states(state_hash,provider,cookie_hash,verifier,nonce,redirect_uri,expires_at) VALUES(?,?,?,?,?,?,?)').bind(await hash(state), provider, await hash(binding), verifier, nonce, redirectUri, Date.now() + FLOW_SECONDS * 1000).run();
  const url = new URL(definitions[provider].authorize);
  const challenge = base64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(verifier))));
  for (const [key, value] of Object.entries({ client_id: config.clientId, redirect_uri: redirectUri, response_type: 'code', scope: definitions[provider].scope, state, nonce, code_challenge: challenge, code_challenge_method: 'S256' })) url.searchParams.set(key, value);
  if (provider === 'google') url.searchParams.set('prompt', 'select_account');
  const headers = new Headers({ Location: url.href, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'Set-Cookie': authCookie(r, binding, FLOW_SECONDS, '_oauth', 'Lax') });
  return new Response(null, { status: 303, headers });
}
export async function finishProvider(r: Request, value: string) {
  const provider = parseProvider(value); if (!provider) return failure(r, 'provider_unknown');
  const config = providerConfig(provider); if (!config || !env.DB) return failure(r, 'provider_unavailable', provider);
  const url = new URL(r.url), state = url.searchParams.get('state'), binding = readCookie(r, cookieName(r, '_oauth'));
  if (!state || !binding || !/^[-\w]{43}$/.test(state) || !/^[-\w]{43}$/.test(binding) || url.searchParams.getAll('state').length !== 1) return failure(r, 'flow_invalid', provider);
  const flow = await env.DB.prepare('DELETE FROM sg_oauth_states WHERE state_hash=? AND provider=? AND cookie_hash=? AND expires_at>? RETURNING verifier,nonce,redirect_uri AS redirectUri').bind(await hash(state), provider, await hash(binding), Date.now()).first<{ verifier: string; nonce: string; redirectUri: string }>();
  if (!flow) return failure(r, 'flow_invalid', provider);
  if (url.searchParams.has('error')) return failure(r, 'cancelled', provider);
  const code = url.searchParams.get('code');
  if (!code || code.length > 2048 || url.searchParams.getAll('code').length !== 1 || flow.redirectUri !== new URL('/api/auth/provider/' + provider + '/callback', r.url).href) return failure(r, 'flow_invalid', provider);
  try {
    const body = new URLSearchParams({ client_id: config.clientId, grant_type: 'authorization_code', code, redirect_uri: flow.redirectUri, code_verifier: flow.verifier });
    const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
    if (provider === 'telegram') headers.Authorization = 'Basic ' + btoa(config.clientId + ':' + config.clientSecret); else body.set('client_secret', config.clientSecret);
    const tokens = await fetchJson(definitions[provider].token, { method: 'POST', headers, body: body.toString() });
    let identity: Pending;
    if (provider === 'github') {
      if (typeof tokens.access_token !== 'string' || !tokens.access_token || tokens.access_token.length > 4096 || String(tokens.token_type).toLowerCase() !== 'bearer') throw Error('github_token');
      const user = await fetchJson('https://api.github.com/user', { headers: { Authorization: 'Bearer ' + tokens.access_token, Accept: 'application/vnd.github+json', 'User-Agent': 'SHADOWGRAPH', 'X-GitHub-Api-Version': '2022-11-28' } });
      if (!Number.isSafeInteger(user.id) || user.id <= 0) throw Error('github_user');
      identity = { provider, subject: String(user.id), name: (typeof user.name === 'string' ? user.name : typeof user.login === 'string' ? user.login : 'GitHub').slice(0, 100) };
    } else identity = await verifyIdentityToken(provider, tokens.id_token, config.clientId, flow.nonce);
    // Provider email and display name never select or merge an existing SHADOWGRAPH account.
    const linked = await env.DB.prepare('SELECT account_id AS accountId FROM sg_identities WHERE provider=? AND subject=?').bind(provider, identity.subject).first<{ accountId: string }>();
    const clearFlow = authCookie(r, '', 0, '_oauth', 'Lax');
    if (linked) {
      const response = await sessionSuccess(r, linked.accountId);
      return redirect(r, '/workspace', [response.headers.get('Set-Cookie')!, clearFlow, clearPendingCookie(r)]);
    }
    const pending = randomToken();
    await env.DB.prepare('INSERT INTO sg_oauth_pending(token_hash,provider,subject,name,expires_at) VALUES(?,?,?,?,?)').bind(await hash(pending), provider, identity.subject, identity.name, Date.now() + FLOW_SECONDS * 1000).run();
    return redirect(r, '/workspace', [authCookie(r, pending, FLOW_SECONDS, '_pending'), clearFlow]);
  } catch { return failure(r, 'provider_failed', provider); }
}
