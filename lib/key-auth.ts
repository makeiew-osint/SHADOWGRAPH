import { env } from 'cloudflare:workers';
const SECONDS=604800,encoder=new TextEncoder();
export const json=(v:unknown,status=200,h:Record<string,string>={})=>Response.json(v,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',...h}});
const owner=(r:Request)=>r.headers.get('oai-authenticated-user-id');
const token=()=>btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const hash=async(s:string)=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(s)))].map(x=>x.toString(16).padStart(2,'0')).join('');
const cookieName=(r:Request)=>new URL(r.url).protocol==='https:'?'__Host-shadowgraph':'shadowgraph_local';
const cookie=(r:Request,v:string,age=SECONDS)=>`${cookieName(r)}=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${new URL(r.url).protocol==='https:'?'; Secure':''}`;
const session=(r:Request)=>(r.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(cookieName(r)+'='))?.split('=')[1];
export const sameOrigin=(r:Request)=>r.headers.get('origin')===new URL(r.url).origin&&r.headers.get('sec-fetch-site')!=='cross-site';
export const nameKey=(s:string)=>s.normalize('NFKC').trim().toLocaleLowerCase('ru-RU').replace(/\s+/g,'_').replace(/[аеорсхуктвмн]/g,c=>({'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y','к':'k','т':'t','в':'b','м':'m','н':'h'}[c]||c));
const reserved=new Set(['admin','administrator','owner','root','shadowgraph','владелец','администратор'].map(nameKey));
export type Account={id:string;name:string;createdAt:number;role:'owner'|'member';vaultKey:string};
const visible=(a:Account)=>({id:a.id,name:a.name,createdAt:a.createdAt,role:a.role});
// Only the existing account on this confirmed owner-private Site becomes its owner.
// An empty fresh deployment remains unconfigured, rather than giving ownership to a public registrant.
export async function initializeAccounts(){
 const setting=await env.DB!.prepare("SELECT value FROM sg_settings WHERE key='owner_account_id'").first<{value:string}>();
 if(!setting){const first=await env.DB!.prepare('SELECT id FROM sg_accounts ORDER BY created_at,id LIMIT 1').first<{id:string}>();await env.DB!.prepare("INSERT OR IGNORE INTO sg_settings(key,value) VALUES('owner_account_id',?)").bind(first?.id||'unconfigured').run()}
 await env.DB!.prepare("UPDATE sg_accounts SET role='owner' WHERE id=(SELECT value FROM sg_settings WHERE key='owner_account_id') AND role<>'owner'").run();
 const old=await env.DB!.prepare('SELECT id,name FROM sg_accounts WHERE name_key IS NULL').all<{id:string;name:string}>();
 for(const a of old.results){try{await env.DB!.prepare('UPDATE sg_accounts SET name_key=? WHERE id=? AND name_key IS NULL').bind(nameKey(a.name),a.id).run()}catch{await env.DB!.prepare('UPDATE sg_accounts SET name_key=? WHERE id=? AND name_key IS NULL').bind(nameKey(a.name)+':legacy:'+a.id,a.id).run()}}
}
async function ensureVault(a:Account){if(!a.vaultKey){await env.DB!.prepare('UPDATE sg_accounts SET vault_key=? WHERE id=? AND vault_key IS NULL').bind(token(),a.id).run();a.vaultKey=(await env.DB!.prepare('SELECT vault_key AS k FROM sg_accounts WHERE id=?').bind(a.id).first<{k:string}>())!.k}return a}
export async function getAccount(r:Request):Promise<Account|null>{
 if(!env.DB)return null;const u=owner(r),s=session(r);if(!u||!s||!/^[-\w]{43}$/.test(s))return null;await initializeAccounts();
 const a=await env.DB.prepare('SELECT a.id,a.name,a.created_at AS createdAt,a.role,a.vault_key AS vaultKey FROM sg_sessions s JOIN sg_accounts a ON a.id=s.account_id WHERE s.token_hash=? AND s.owner=? AND a.owner=? AND s.expires_at>?').bind(await hash(s),u,u,Date.now()).first<Account>();return a?ensureVault(a):null;
}
export async function authStatus(r:Request){const a=await getAccount(r);return json({account:a?visible(a):null,...(a?{vaultKey:a.vaultKey}:{}),signIn:owner(r)?null:'/signin-with-chatgpt?return_to=/workspace',providers:{key:true,google:false,telegram:false,github:false}})}
async function rate(scope:string,u:string,duration:number,max:number){const row=await env.DB!.prepare('INSERT INTO sg_auth_attempts(id,count,expires_at) VALUES(?,1,?) ON CONFLICT(id) DO UPDATE SET count=count+1 RETURNING count').bind(`${scope}:${u}:${Math.floor(Date.now()/duration)}`,Date.now()+duration*2).first<{count:number}>();return!!row&&row.count<=max}
async function success(r:Request,id:string,u:string,status=200){const row=await env.DB!.prepare('SELECT id,name,role,created_at AS createdAt,vault_key AS vaultKey FROM sg_accounts WHERE id=? AND owner=?').bind(id,u).first<Account>();if(!row)throw Error('Account missing');const a=await ensureVault(row),secret=token();await env.DB!.prepare('INSERT INTO sg_sessions(token_hash,account_id,owner,expires_at) VALUES(?,?,?,?)').bind(await hash(secret),id,u,Date.now()+SECONDS*1000).run();return json({account:visible(a),vaultKey:a.vaultKey},status,{'Set-Cookie':cookie(r,secret)})}
export async function authAction(r:Request){
 if(!env.DB)return json({error:'Сервис входа ещё не готов.'},503);const u=owner(r);if(!u)return json({error:'Сначала войдите через ChatGPT.',signIn:'/signin-with-chatgpt?return_to=/workspace'},401);if(!sameOrigin(r))return json({error:'Недопустимый источник запроса.'},403);
 if(Number(r.headers.get('content-length')||0)>2048)return json({error:'Слишком большой запрос.'},413);
 let b:{action?:string;key?:string;name?:string};try{const raw=await r.text();if(raw.length>2048)return json({error:'Слишком большой запрос.'},413);b=JSON.parse(raw)}catch{return json({error:'Неверный запрос.'},400)}if(!b||typeof b!=='object'||Array.isArray(b))return json({error:'Неверный запрос.'},400);
 await initializeAccounts();await env.DB.batch([env.DB.prepare('DELETE FROM sg_auth_attempts WHERE expires_at<?').bind(Date.now()),env.DB.prepare('DELETE FROM sg_sessions WHERE expires_at<?').bind(Date.now())]);
 if(b.action==='register'){
  if(!await rate('register',u,3600000,10))return json({error:'Слишком много попыток регистрации.'},429);
  const name=typeof b.name==='string'?b.name.normalize('NFKC').trim():'';if(!/^[\p{L}\p{N}_.-]{3,32}$/u.test(name))return json({error:'Ник: 3–32 буквы или цифры, точка, дефис и подчёркивание.'},400);const canonical=nameKey(name);if(reserved.has(canonical))return json({error:'Этот ник зарезервирован.'},409);if(await env.DB.prepare('SELECT id FROM sg_accounts WHERE name_key=?').bind(canonical).first())return json({error:'Этот ник уже занят. Выберите другой.'},409);
  const key=typeof b.key==='string'?b.key.trim():'';if(!/^SGM-[-\w]{43}$/.test(key))return json({error:'Нужен ключ участника SGM-…, выданный владельцем.'},400);const kh=await hash(key),id=crypto.randomUUID(),vk=token();if(!await env.DB.prepare('SELECT id FROM sg_invites WHERE key_hash=? AND claimed_by IS NULL AND revoked_at IS NULL').bind(kh).first())return json({error:'Ключ недействителен или уже активирован.'},401);
  let result;try{result=await env.DB.batch([env.DB.prepare("INSERT INTO sg_accounts(id,owner,name,name_key,key_hash,created_at,role,vault_key) SELECT ?,?,?,?,?,?,'member',? WHERE EXISTS(SELECT 1 FROM sg_invites WHERE key_hash=? AND claimed_by IS NULL AND revoked_at IS NULL)").bind(id,u,name,canonical,kh,Date.now(),vk,kh),env.DB.prepare('UPDATE sg_invites SET claimed_by=?,claimed_at=? WHERE key_hash=? AND claimed_by IS NULL AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM sg_accounts WHERE id=?)').bind(id,Date.now(),kh,id)])}catch(e){if(String(e).includes('UNIQUE'))return json({error:'Ник или ключ уже использован.'},409);throw e}if(!result[0].meta.changes)return json({error:'Этот ключ уже активирован.'},409);return success(r,id,u,201);
 }
 if(b.action==='login'){
  if(!await rate('login',u,60000,15))return json({error:'Слишком много попыток. Подождите минуту.'},429);const key=typeof b.key==='string'?b.key.trim():'';if(!/^SG(?:1|M)-[-\w]{43}$/.test(key))return json({error:'Ключ не найден или недействителен.'},401);const kh=await hash(key),a=await env.DB.prepare('SELECT id FROM sg_accounts WHERE key_hash=? AND owner=?').bind(kh,u).first<{id:string}>();if(a)return success(r,a.id,u);if(await env.DB.prepare('SELECT id FROM sg_invites WHERE key_hash=? AND claimed_by IS NULL AND revoked_at IS NULL').bind(kh).first())return json({needsRegistration:true});return json({error:'Ключ недействителен или привязан к другому аккаунту ChatGPT.'},401);
 }
 if(b.action==='logout'){const raw=session(r);if(raw)await env.DB.prepare('DELETE FROM sg_sessions WHERE token_hash=? AND owner=?').bind(await hash(raw),u).run();return json({ok:true},200,{'Set-Cookie':cookie(r,'',0)})}
 return json({error:'Неизвестное действие.'},400);
}
export async function issueMemberKeys(r:Request){
 if(!sameOrigin(r))return json({error:'Недопустимый источник запроса.'},403);const a=await getAccount(r);if(!a)return json({error:'Войдите в аккаунт.'},401);if(a.role!=='owner')return json({error:'Только владелец может выпускать ключи участников.'},403);
 let b:{count?:number;batchId?:string};try{b=await r.json()}catch{return json({error:'Неверный запрос.'},400)}if(!b||b.count!==10||typeof b.batchId!=='string'||!/^[-\w]{20,80}$/.test(b.batchId))return json({error:'Допустим выпуск ровно 10 ключей с уникальным номером партии.'},400);if(await env.DB!.prepare('SELECT id FROM sg_invites WHERE batch_id=? LIMIT 1').bind(b.batchId).first())return json({error:'Партия уже выпущена. Повторный показ ключей недоступен.'},409);if(!await rate('invites',a.id,3600000,10))return json({error:'Достигнут лимит выпуска.'},429);
 const keys=Array.from({length:10},(_,i)=>({number:i+1,key:'SGM-'+token()}));await env.DB!.batch(await Promise.all(keys.map(async item=>env.DB!.prepare('INSERT INTO sg_invites(id,batch_id,slot,key_hash,created_by,created_at) VALUES(?,?,?,?,?,?)').bind(crypto.randomUUID(),b.batchId,item.number,await hash(item.key),a.id,Date.now()))));return json({keys,role:'member',batchId:b.batchId},201);
}
