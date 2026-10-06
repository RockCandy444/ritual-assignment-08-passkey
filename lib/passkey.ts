import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse,
  type RegistrationResponseJSON, type AuthenticationResponseJSON, type AuthenticatorTransport } from '@simplewebauthn/server';
import { db } from './db';
import { AppError, json, token, hash, readCookie, setCookie, body, field, requireSameOrigin, toBase64, fromBase64 } from './security';

type User = {id: string; display_name: string};
type Session = {token_hash: string; user_id: string; credential_id: string; expires_at: number; display_name: string; created_at: number};
type Key = {id: string; user_id: string; public_key: string; counter: number; name: string; storage: string; transports: string; device_type: string; backed_up: number; created_at: number; revoked_at: number | null};
type Challenge = {id: string; flow_hash: string; challenge: string; kind: string; user_id: string; display_name: string; key_name: string; storage: string; session_hash: string | null; expires_at: number; consumed_at: number | null};
const storageNames = ['기기 자체', '구글 비밀번호 관리자', '보안 키', '다른 비밀번호 관리자'];
const TTL = 300_000;

function config(req: Request) {
  // Origin is taken from the runtime Request URL, never a body/forwarded header.
  const url = new URL(req.url);
  if (url.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(url.hostname)) throw new AppError(400, 'HTTPS_REQUIRED', '패스키는 HTTPS 주소에서 사용해 주세요.');
  return {origin: url.origin, rpID: url.hostname, rpName: '솜사탕의 나만의 메모함'};
}
export async function session(req: Request): Promise<Session | null> {
  const raw = readCookie(req, 'session'); if (!raw) return null;
  return db().prepare(`SELECT s.*, u.display_name FROM sessions s JOIN users u ON u.id=s.user_id
    JOIN passkeys p ON p.id=s.credential_id AND p.user_id=s.user_id AND p.revoked_at IS NULL
    WHERE s.token_hash=? AND s.expires_at>?`).bind(await hash(raw), Date.now()).first<Session>();
}
async function requireSession(req: Request) {
  const s = await session(req); if (!s) throw new AppError(401, 'LOGIN_REQUIRED', '패스키로 메모함을 먼저 열어 주세요.'); return s;
}
async function rateLimit(req: Request, scope: string) {
  const now = Date.now(); const ip = req.headers.get('CF-Connecting-IP') || 'local';
  const bucket = await hash(`${scope}:${ip}:${Math.floor(now / 60000)}`);
  const r = await db().prepare(`INSERT INTO rate_limits(bucket,count,expires_at) VALUES(?,1,?)
    ON CONFLICT(bucket) DO UPDATE SET count=count+1 RETURNING count`).bind(bucket, now + 120000).first<{count: number}>();
  if ((r?.count || 0) > 40) throw new AppError(429, 'TOO_MANY_REQUESTS', '잠시 기다린 뒤 다시 시도해 주세요.');
  await db().batch([db().prepare('DELETE FROM rate_limits WHERE expires_at<?').bind(now),
    db().prepare('DELETE FROM challenges WHERE expires_at<?').bind(now - 86400000),
    db().prepare('DELETE FROM sessions WHERE expires_at<?').bind(now)]);
}
async function remember(req: Request, options: {challenge: string}, pending: Omit<Challenge, 'id' | 'flow_hash' | 'challenge' | 'expires_at' | 'consumed_at'>, headers: Headers) {
  const flow = readCookie(req, 'flow') || token(); const now = Date.now();
  await db().prepare(`INSERT INTO challenges(id,flow_hash,challenge,kind,user_id,display_name,key_name,storage,session_hash,created_at,expires_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(crypto.randomUUID(), await hash(flow), options.challenge, pending.kind, pending.user_id,
      pending.display_name, pending.key_name, pending.storage, pending.session_hash, now, now + TTL).run();
  setCookie(headers, req, 'flow', flow, TTL / 1000);
}
function responseObject(value: unknown): RegistrationResponseJSON | AuthenticationResponseJSON {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new AppError(400, 'INVALID_CREDENTIAL', '패스키 응답을 확인해 주세요.');
  const response = value as RegistrationResponseJSON;
  if (typeof response.id !== 'string' || response.id.length > 2048 || typeof response.response?.clientDataJSON !== 'string') throw new AppError(400, 'INVALID_CREDENTIAL', '패스키 응답을 확인해 주세요.');
  return response;
}
async function consume(req: Request, response: RegistrationResponseJSON | AuthenticationResponseJSON, kind: 'registration' | 'login') {
  const flow = readCookie(req, 'flow'); if (!flow) throw new AppError(400, 'CHALLENGE_INVALID', '요청이 만료됐어요. 다시 시도해 주세요.');
  let challenge: string;
  try { challenge = JSON.parse(new TextDecoder().decode(fromBase64(response.response.clientDataJSON))).challenge; }
  catch { throw new AppError(400, 'INVALID_CREDENTIAL', '패스키 응답을 확인해 주세요.'); }
  if (typeof challenge !== 'string' || challenge.length > 256) throw new AppError(400, 'CHALLENGE_INVALID', '요청을 확인할 수 없어요.');
  // Atomic claim: parallel/replayed requests cannot consume the same challenge twice.
  const row = await db().prepare(`UPDATE challenges SET consumed_at=? WHERE id=(SELECT id FROM challenges
    WHERE flow_hash=? AND challenge=? AND kind IN (?,?) AND consumed_at IS NULL AND expires_at>? LIMIT 1)
    AND consumed_at IS NULL RETURNING *`).bind(Date.now(), await hash(flow), challenge,
      kind === 'registration' ? 'signup' : 'login', kind === 'registration' ? 'register' : 'login', Date.now()).first<Challenge>();
  if (!row) throw new AppError(400, 'CHALLENGE_INVALID', '이미 사용했거나 만료된 요청이에요. 다시 시도해 주세요.');
  return row;
}
async function optionsRegistration(req: Request, data: Record<string, unknown>, headers: Headers) {
  await rateLimit(req, 'options'); const c = config(req); const s = await session(req);
  const signup = data.mode === 'signup';
  if (!signup && data.mode !== 'register') throw new AppError(400, 'INVALID_MODE', '등록 방식을 확인해 주세요.');
  if (signup && s) throw new AppError(409, 'ALREADY_SIGNED_IN', '새 메모함은 로그아웃한 뒤 만들어 주세요.');
  if (!signup && !s) throw new AppError(401, 'LOGIN_REQUIRED', '패스키 추가는 로그인한 뒤 할 수 있어요.');
  if (!signup && Date.now()-s!.created_at > 600000) throw new AppError(403, 'REAUTH_REQUIRED', '패스키를 추가하려면 다시 로그인해 주세요.');
  const displayName = signup ? field(data.displayName, '별명', 30) : s!.display_name;
  const keyName = field(data.keyName, '패스키 이름', 50);
  if (!storageNames.includes(data.storage as string)) throw new AppError(400, 'INVALID_STORAGE', '패스키 저장 위치를 선택해 주세요.');
  const userId = signup ? crypto.randomUUID() : s!.user_id;
  const keys = signup ? [] : (await db().prepare('SELECT * FROM passkeys WHERE user_id=? AND revoked_at IS NULL').bind(userId).all<Key>()).results;
  if (keys.length >= 8) throw new AppError(409, 'KEY_LIMIT', '패스키는 최대 8개까지 등록할 수 있어요.');
  const options = await generateRegistrationOptions({rpName: c.rpName, rpID: c.rpID,
    userID: new TextEncoder().encode(userId), userName: `${displayName} · ${userId.slice(0, 8)}`, userDisplayName: displayName,
    attestationType: 'none', authenticatorSelection: {residentKey: 'required', userVerification: 'required'},
    ...(data.storage==='기기 자체' ? {preferredAuthenticatorType:'localDevice' as const} : data.storage==='보안 키' ? {preferredAuthenticatorType:'securityKey' as const} : data.storage==='구글 비밀번호 관리자' ? {preferredAuthenticatorType:'remoteDevice' as const} : {}),
    supportedAlgorithmIDs: [-7, -257], excludeCredentials: keys.map(k => ({id:k.id, transports: JSON.parse(k.transports)}))});
  await remember(req, options, {kind: signup ? 'signup' : 'register', user_id:userId, display_name:displayName,
    key_name:keyName, storage: data.storage as string, session_hash:s?.token_hash || null}, headers);
  return json({options, expiresIn: TTL / 1000}, 200, headers);
}
async function verifyRegistration(req: Request, data: Record<string, unknown>, headers: Headers) {
  const response = responseObject(data.response) as RegistrationResponseJSON;
  const ch = await consume(req, response, 'registration'); const c = config(req);
  if (ch.kind === 'register') {
    const s = await requireSession(req);
    if (s.token_hash !== ch.session_hash || s.user_id !== ch.user_id) throw new AppError(403, 'REGISTRATION_DENIED', '등록을 시작한 계정으로 다시 로그인해 주세요.');
    if (Date.now()-s.created_at > 600000) throw new AppError(403,'REAUTH_REQUIRED','패스키를 추가하려면 다시 로그인해 주세요.');
  } else if (await session(req)) throw new AppError(409, 'ALREADY_SIGNED_IN', '로그아웃한 뒤 새 메모함을 만들어 주세요.');
  let result;
  try { result = await verifyRegistrationResponse({response, expectedChallenge:ch.challenge, expectedOrigin:c.origin, expectedRPID:c.rpID, requireUserVerification:true, supportedAlgorithmIDs:[-7,-257]}); }
  catch(error) { console.error('T08 registration verification:', error instanceof Error ? error.message : 'unknown'); throw new AppError(400, 'REGISTRATION_INVALID', '패스키 등록을 확인하지 못했어요. 다시 시도해 주세요.'); }
  if (!result.verified || !result.registrationInfo) throw new AppError(400, 'REGISTRATION_INVALID', '패스키 등록을 확인하지 못했어요.');
  const info = result.registrationInfo; const key = info.credential; const now = Date.now();
  const exists = await db().prepare('SELECT id FROM passkeys WHERE id=?').bind(key.id).first();
  if (exists) throw new AppError(409, 'ALREADY_REGISTERED', '이미 등록된 패스키예요. 다른 저장 위치를 선택해 주세요.');
  const statements: D1PreparedStatement[] = [];
  const rawSession = token(); const sessionHash = await hash(rawSession);
  if (ch.kind === 'signup') statements.push(db().prepare('INSERT INTO users(id,display_name,created_at) VALUES(?,?,?)').bind(ch.user_id,ch.display_name,now));
  // Additional registration inserts only while its original session is still valid.
  statements.push(db().prepare(`INSERT INTO passkeys(id,user_id,public_key,counter,name,storage,transports,device_type,backed_up,created_at)
    SELECT ?,?,?,?,?,?,?,?,?,? WHERE ?='signup' OR EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND expires_at>?)`).bind(
    key.id,ch.user_id,toBase64(key.publicKey),key.counter,ch.key_name,ch.storage,JSON.stringify(key.transports || []),info.credentialDeviceType,
    info.credentialBackedUp ? 1 : 0,now,ch.kind,ch.session_hash,ch.user_id,now));
  if (ch.kind === 'signup') {
    const examples = [
      ['프로젝트 메모', '작은 전시 페이지 준비', `${ch.display_name}의 가상 프로젝트: 작품 카드 세 장과 소개 문장을 만들어 보는 연습.`],
      ['지원 계획', '연습용 지원 목록', `${ch.display_name}의 가상 계획: 가상의 팀 ‘구름 작업실’과 ‘별빛 스튜디오’ 소개를 읽어 보기.`],
      ['돌아보기', '오늘의 연습 회고', `${ch.display_name}의 가상 회고: 막힌 부분을 한 번에 해결하려 하지 않고 작은 단계로 나눠 보았다.`],
    ];
    for (const [category,title,noteBody] of examples) statements.push(db().prepare('INSERT INTO notes(id,user_id,category,title,body,updated_at) VALUES(?,?,?,?,?,?)').bind(crypto.randomUUID(),ch.user_id,category,title,noteBody,now));
    statements.push(db().prepare('INSERT INTO sessions(token_hash,user_id,credential_id,created_at,expires_at) VALUES(?,?,?,?,?)').bind(sessionHash,ch.user_id,key.id,now,now+43200000));
  }
  const saved = await db().batch(statements);
  const keyInsert = saved[ch.kind === 'signup' ? 1 : 0];
  if (keyInsert.meta.changes !== 1) throw new AppError(401, 'LOGIN_REQUIRED', '로그인이 종료됐어요. 다시 로그인한 뒤 등록해 주세요.');
  if (ch.kind === 'signup') setCookie(headers,req,'session',rawSession,43200);
  return json({verified:true, user:{id:ch.user_id, displayName:ch.display_name}, passkey:{id:key.id,name:ch.key_name,storage:ch.storage,createdAt:now}},201,headers);
}
async function optionsLogin(req: Request, headers: Headers) {
  await rateLimit(req, 'options'); const c = config(req);
  const options = await generateAuthenticationOptions({rpID:c.rpID,userVerification:'required',allowCredentials:[]});
  await remember(req,options,{kind:'login',user_id:'',display_name:'',key_name:'',storage:'',session_hash:null},headers);
  return json({options,expiresIn:TTL / 1000},200,headers);
}
async function verifyLogin(req: Request, data: Record<string, unknown>, headers: Headers) {
  const response = responseObject(data.response) as AuthenticationResponseJSON;
  const ch = await consume(req,response,'login'); const c = config(req);
  const key = await db().prepare('SELECT * FROM passkeys WHERE id=? AND revoked_at IS NULL').bind(response.id).first<Key>();
  if (!key) throw new AppError(401,'PASSKEY_UNKNOWN','등록되지 않았거나 삭제된 패스키예요. 다른 등록된 패스키를 선택해 주세요.');
  let result;
  try { result = await verifyAuthenticationResponse({response,expectedChallenge:ch.challenge,expectedOrigin:c.origin,expectedRPID:c.rpID,requireUserVerification:true,
    credential:{id:key.id,publicKey:fromBase64(key.public_key),counter:key.counter,transports:JSON.parse(key.transports) as AuthenticatorTransport[]}}); }
  catch { throw new AppError(401,'SIGNATURE_INVALID','패스키를 확인하지 못했어요. 다시 시도해 주세요.'); }
  if (!result.verified) throw new AppError(401,'SIGNATURE_INVALID','패스키를 확인하지 못했어요.');
  if (response.response.userHandle && new TextDecoder().decode(fromBase64(response.response.userHandle)) !== key.user_id) throw new AppError(401,'USER_HANDLE_INVALID','패스키의 계정을 확인하지 못했어요.');
  const now = Date.now(); const raw = token(); const h = await hash(raw);
  // CAS counter and revocation check remain valid even when deletion races this request.
  const results = await db().batch([
    db().prepare('UPDATE passkeys SET counter=? WHERE id=? AND counter=? AND revoked_at IS NULL').bind(result.authenticationInfo.newCounter,key.id,key.counter),
    db().prepare(`INSERT INTO sessions(token_hash,user_id,credential_id,created_at,expires_at)
      SELECT ?,?,?,?,? WHERE changes()=1 AND EXISTS(SELECT 1 FROM passkeys WHERE id=? AND revoked_at IS NULL)`).bind(h,key.user_id,key.id,now,now+43200000,key.id),
  ]);
  if (results[1].meta.changes !== 1) throw new AppError(401,'PASSKEY_CHANGED','패스키 상태가 바뀌었어요. 다시 시도해 주세요.');
  const previous = readCookie(req,'session'); if (previous) await db().prepare('DELETE FROM sessions WHERE token_hash=?').bind(await hash(previous)).run();
  setCookie(headers,req,'session',raw,43200);
  const user = await db().prepare('SELECT id,display_name FROM users WHERE id=?').bind(key.user_id).first<User>();
  return json({verified:true,user:{id:user!.id,displayName:user!.display_name}},200,headers);
}
async function revoke(req: Request, data: Record<string, unknown>, headers: Headers) {
  const s = await requireSession(req);
  // Require recent passkey verification before credential management.
  if (Date.now()-s.created_at > 600000) throw new AppError(403,'REAUTH_REQUIRED','패스키를 삭제하려면 다시 로그인해 주세요.');
  const id = field(data.id,'패스키',2048);
  const key = await db().prepare('SELECT id,user_id FROM passkeys WHERE id=? AND revoked_at IS NULL').bind(id).first<Key>();
  if (!key || key.user_id!==s.user_id) throw new AppError(403,'KEY_FORBIDDEN','이 계정의 패스키만 관리할 수 있어요.');
  const results = await db().batch([
    db().prepare(`UPDATE passkeys SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL
      AND (SELECT COUNT(*) FROM passkeys WHERE user_id=? AND revoked_at IS NULL)>1
      AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND expires_at>?)`).bind(Date.now(),id,s.user_id,s.user_id,s.token_hash,Date.now()),
    db().prepare('DELETE FROM sessions WHERE user_id=? AND changes()=1').bind(s.user_id),
    db().prepare(`UPDATE challenges SET consumed_at=? WHERE user_id=? AND kind='register' AND consumed_at IS NULL
      AND EXISTS(SELECT 1 FROM passkeys WHERE id=? AND revoked_at IS NOT NULL)`).bind(Date.now(),s.user_id,id),
  ]);
  if (results[0].meta.changes!==1) throw new AppError(409,'LAST_PASSKEY','마지막 패스키는 삭제할 수 없어요. 다른 패스키를 먼저 추가해 주세요.');
  setCookie(headers,req,'session','',0);
  return json({deleted:true,signedOut:true,message:'패스키를 삭제했어요. 남은 패스키로 다시 로그인해 주세요.'},200,headers);
}
export async function privateData(req: Request) {
  try {
    const s = await requireSession(req); const url = new URL(req.url);
    const parts = url.pathname.split('/').filter(Boolean);
    // Explicit object ownership check; supplied account IDs never select the owner.
    if (parts[1]==='private' && parts[2]==='notes' && parts[3]) {
      const note = await db().prepare('SELECT * FROM notes WHERE id=?').bind(parts[3]).first<{user_id:string}>();
      if (!note || note.user_id!==s.user_id) throw new AppError(403,'NOTE_FORBIDDEN','다른 계정의 메모는 열 수 없어요.');
      return json({note});
    }
    const values = (await db().prepare('SELECT id,category,title,body,updated_at FROM notes WHERE user_id=? ORDER BY updated_at,id').bind(s.user_id).all()).results;
    return json({user:{id:s.user_id,displayName:s.display_name},notes:values,fictional:true});
  } catch(error) { return fail(error); }
}
function fail(error: unknown) {
  if (error instanceof AppError) return json({error:error.code,message:error.message},error.status);
  console.error('T08 request failed',error instanceof Error ? error.message : 'unknown');
  return json({error:'TEMPORARILY_UNAVAILABLE',message:'잠시 메모함을 사용할 수 없어요. 잠시 후 다시 시도해 주세요.'},503);
}
export async function handle(req: Request) {
  const path = new URL(req.url).pathname.replace('/api/passkey/',''); const headers = new Headers();
  try {
    if (req.method==='GET') {
      if (path==='session') { const s=await session(req); return json({user:s ? {id:s.user_id,displayName:s.display_name} : null}); }
      if (path==='keys') {
        const s=await requireSession(req);
        const keys=(await db().prepare('SELECT id,name,storage,created_at,device_type,backed_up FROM passkeys WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at,id').bind(s.user_id).all()).results;
        return json({keys});
      }
      if (path==='evidence') {
        const s=await requireSession(req);
        const keys=(await db().prepare('SELECT id,name,storage,public_key,created_at,revoked_at FROM passkeys WHERE user_id=? ORDER BY created_at,id').bind(s.user_id).all()).results;
        return json({capturedAt:new Date().toISOString(),user:{id:s.user_id,displayName:s.display_name},keys,
          publicKeyEncoding:'COSE public key, base64url; not a password',storageSource:'user-selected; check the actual passkey provider',privateKeysIncluded:false});
      }
      throw new AppError(404,'NOT_FOUND','요청한 페이지가 없어요.');
    }
    requireSameOrigin(req); const data=await body(req);
    if (req.method==='POST' && path==='register/options') return await optionsRegistration(req,data,headers);
    if (req.method==='POST' && path==='register/verify') return await verifyRegistration(req,data,headers);
    if (req.method==='POST' && path==='login/options') return await optionsLogin(req,headers);
    if (req.method==='POST' && path==='login/verify') return await verifyLogin(req,data,headers);
    if (req.method==='POST' && path==='cancel') {
      const flow=readCookie(req,'flow');
      if (flow) await db().prepare('UPDATE challenges SET consumed_at=? WHERE flow_hash=? AND consumed_at IS NULL').bind(Date.now(),await hash(flow)).run();
      setCookie(headers,req,'flow','',0); return json({cancelled:true},200,headers);
    }
    if (req.method==='POST' && path==='logout') {
      const raw=readCookie(req,'session'); if (raw) await db().prepare('DELETE FROM sessions WHERE token_hash=?').bind(await hash(raw)).run();
      const flow=readCookie(req,'flow'); if(flow) await db().prepare('UPDATE challenges SET consumed_at=? WHERE flow_hash=? AND consumed_at IS NULL').bind(Date.now(),await hash(flow)).run();
      setCookie(headers,req,'session','',0); setCookie(headers,req,'flow','',0); return json({signedOut:true},200,headers);
    }
    if (req.method==='DELETE' && path==='keys') return await revoke(req,data,headers);
    throw new AppError(404,'NOT_FOUND','요청한 페이지가 없어요.');
  } catch(error) { return fail(error); }
}
