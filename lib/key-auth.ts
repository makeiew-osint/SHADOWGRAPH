import { env } from 'cloudflare:workers';
import { authCookie, authRate, cookieName, getAccount, hash, initializeAccounts, json, nameKey, randomToken, readCookie, readSmallJson, requestIdentity, sameOrigin, sessionSuccess, visibleAccount } from './auth-shared';
import { attachPendingIdentity, clearPendingCookie, pendingIdentity, providerStatus } from './social-auth';
export { getAccount, json, nameKey, sameOrigin, initializeAccounts } from './auth-shared';
const reserved = new Set(['admin', 'administrator', 'owner', 'root', 'shadowgraph', 'владелец', 'администратор'].map(nameKey));
export async function authStatus(r: Request) {
  const account = await getAccount(r), pending = env.DB ? await pendingIdentity(r) : null;
  return json({ account: account ? visibleAccount(account) : null, ...(account ? { vaultKey: account.vaultKey } : {}), signIn: null, providers: providerStatus(), pendingProvider: pending ? { provider: pending.provider, name: pending.name } : null });
}
async function loginSuccess(r: Request, id: string, status = 200) {
  const providerLink = await attachPendingIdentity(r, id);
  const response = await sessionSuccess(r, id, status, providerLink ? { providerLink } : {});
  response.headers.append('Set-Cookie', clearPendingCookie(r));
  return response;
}
export async function authAction(r: Request) {
  if (!env.DB) return json({ error: 'Сервис входа ещё не готов.' }, 503);
  if (!sameOrigin(r)) return json({ error: 'Недопустимый источник запроса.' }, 403);
  let b: { action?: string; key?: string; name?: string };
  try { b = await readSmallJson(r); } catch (error) { return json({ error: String(error).includes('body_limit') ? 'Слишком большой запрос.' : 'Неверный запрос.' }, String(error).includes('body_limit') ? 413 : 400); }
  await initializeAccounts();
  await env.DB.batch([env.DB.prepare('DELETE FROM sg_auth_attempts WHERE expires_at<?').bind(Date.now()), env.DB.prepare('DELETE FROM sg_sessions WHERE expires_at<?').bind(Date.now())]);
  if (b.action === 'logout') {
    const raw = readCookie(r, cookieName(r));
    if (raw && /^[-\w]{43}$/.test(raw)) await env.DB.prepare('DELETE FROM sg_sessions WHERE token_hash=?').bind(await hash(raw)).run();
    const response = json({ ok: true }, 200, { 'Set-Cookie': authCookie(r, '', 0) });
    response.headers.append('Set-Cookie', clearPendingCookie(r));
    return response;
  }
  const identity = await requestIdentity(r);
  if (b.action === 'register') {
    if (!await authRate('register', identity, 3600000, 10)) return json({ error: 'Слишком много попыток регистрации.' }, 429);
    const name = typeof b.name === 'string' ? b.name.normalize('NFKC').trim() : '';
    if (!/^[\p{L}\p{N}_.-]{3,32}$/u.test(name)) return json({ error: 'Ник: 3–32 буквы или цифры, точка, дефис и подчёркивание.' }, 400);
    const canonical = nameKey(name);
    if (reserved.has(canonical)) return json({ error: 'Этот ник зарезервирован.' }, 409);
    if (await env.DB.prepare('SELECT id FROM sg_accounts WHERE name_key=?').bind(canonical).first()) return json({ error: 'Этот ник уже занят. Выберите другой.' }, 409);
    const key = typeof b.key === 'string' ? b.key.trim() : '';
    if (!/^SGM-[-\w]{43}$/.test(key)) return json({ error: 'Нужен ключ участника SGM-…, выданный владельцем.' }, 400);
    const kh = await hash(key), id = crypto.randomUUID(), vaultKey = randomToken();
    if (!await env.DB.prepare('SELECT id FROM sg_invites WHERE key_hash=? AND claimed_by IS NULL AND revoked_at IS NULL').bind(kh).first()) return json({ error: 'Ключ недействителен или уже активирован.' }, 401);
    let result;
    try {
      result = await env.DB.batch([
        env.DB.prepare("INSERT INTO sg_accounts(id,owner,name,name_key,key_hash,created_at,role,vault_key) SELECT ?,?,?,?,?,?,'member',? WHERE EXISTS(SELECT 1 FROM sg_invites WHERE key_hash=? AND claimed_by IS NULL AND revoked_at IS NULL)").bind(id, 'key:' + id, name, canonical, kh, Date.now(), vaultKey, kh),
        env.DB.prepare('UPDATE sg_invites SET claimed_by=?,claimed_at=? WHERE key_hash=? AND claimed_by IS NULL AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM sg_accounts WHERE id=?)').bind(id, Date.now(), kh, id),
      ]);
    } catch (error) { if (String(error).includes('UNIQUE')) return json({ error: 'Ник или ключ уже использован.' }, 409); throw error; }
    if (!result[0].meta.changes) return json({ error: 'Этот ключ уже активирован.' }, 409);
    return loginSuccess(r, id, 201);
  }
  if (b.action === 'login') {
    if (!await authRate('login', identity, 60000, 15)) return json({ error: 'Слишком много попыток. Подождите минуту.' }, 429);
    const key = typeof b.key === 'string' ? b.key.trim() : '';
    if (!/^SG(?:1|M)-[-\w]{43}$/.test(key)) return json({ error: 'Ключ не найден или недействителен.' }, 401);
    const kh = await hash(key), account = await env.DB.prepare('SELECT id FROM sg_accounts WHERE key_hash=?').bind(kh).first<{ id: string }>();
    if (account) return loginSuccess(r, account.id);
    if (await env.DB.prepare('SELECT id FROM sg_invites WHERE key_hash=? AND claimed_by IS NULL AND revoked_at IS NULL').bind(kh).first()) return json({ needsRegistration: true });
    return json({ error: 'Ключ не найден или недействителен.' }, 401);
  }
  return json({ error: 'Неизвестное действие.' }, 400);
}
export async function issueMemberKeys(r: Request) {
  if (!sameOrigin(r)) return json({ error: 'Недопустимый источник запроса.' }, 403);
  const account = await getAccount(r);
  if (!account) return json({ error: 'Войдите в аккаунт.' }, 401);
  if (account.role !== 'owner') return json({ error: 'Только владелец может выпускать ключи участников.' }, 403);
  let b: { count?: number; batchId?: string };
  try { b = await readSmallJson(r); } catch { return json({ error: 'Неверный запрос.' }, 400); }
  if (b.count !== 10 || typeof b.batchId !== 'string' || !/^[-\w]{20,80}$/.test(b.batchId)) return json({ error: 'Допустим выпуск ровно 10 ключей с уникальным номером партии.' }, 400);
  if (await env.DB!.prepare('SELECT id FROM sg_invites WHERE batch_id=? LIMIT 1').bind(b.batchId).first()) return json({ error: 'Партия уже выпущена. Повторный показ ключей недоступен.' }, 409);
  if (!await authRate('invites', account.id, 3600000, 10)) return json({ error: 'Достигнут лимит выпуска.' }, 429);
  const keys = Array.from({ length: 10 }, (_, i) => ({ number: i + 1, key: 'SGM-' + randomToken() }));
  await env.DB!.batch(await Promise.all(keys.map(async item => env.DB!.prepare('INSERT INTO sg_invites(id,batch_id,slot,key_hash,created_by,created_at) VALUES(?,?,?,?,?,?)').bind(crypto.randomUUID(), b.batchId, item.number, await hash(item.key), account.id, Date.now()))));
  return json({ keys, role: 'member', batchId: b.batchId }, 201);
}
