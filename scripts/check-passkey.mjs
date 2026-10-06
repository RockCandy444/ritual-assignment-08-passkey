// Real HTTP + real WebAuthn-shaped ECDSA signatures, synthesized in Node.
// This is an engineering test, not evidence of Windows Hello/hardware registration.
import assert from 'node:assert/strict';
import { createHash, randomBytes, webcrypto } from 'node:crypto';
import { encodeCBOR, decodeCBOR } from '@levischuck/tiny-cbor';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { mkdirSync, writeFileSync } from 'node:fs';
const origin=process.env.T08_TEST_ORIGIN || 'http://127.0.0.1:5178';
const hostname=new URL(origin).hostname;
const evidence=[];let checks=0;
const sha=value=>createHash('sha256').update(value).digest();
const b64=value=>Buffer.from(value).toString('base64url');
function check(value,message){assert.ok(value,message);checks++;}
class Browser {
  cookies=new Map();
  async request(path,method='GET',data,extra={}){
    const sent=data===undefined?undefined:JSON.stringify(data);
    const response=await fetch(origin+path,{method,headers:{...(method!=='GET'?{'Content-Type':'application/json',Origin:origin}:{}),
      ...(this.cookies.size?{Cookie:[...this.cookies].map(([k,v])=>`${k}=${v}`).join('; ')}:{}),...extra},body:sent});
    for(const line of response.headers.getSetCookie()){const [pair]=line.split(';');const i=pair.indexOf('=');const k=pair.slice(0,i),v=pair.slice(i+1);if(!v)this.cookies.delete(k);else this.cookies.set(k,v);}
    const text=await response.text();let result;try{result=JSON.parse(text);}catch{result={text};}
    evidence.push({request:{method,path,headers:{...(method!=='GET'?{Origin:extra.Origin||origin,'Content-Type':'application/json'}:{}),...(this.cookies.size?{Cookie:'[REDACTED]'}:{})},body:data??null},response:{status:response.status,body:result,'Cache-Control':response.headers.get('Cache-Control'),'Set-Cookie':response.headers.getSetCookie().length?'[REDACTED]':null}});
    return {status:response.status,body:result,headers:response.headers};
  }
}
async function authenticator(userId){
  const pair=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const jwk=await webcrypto.subtle.exportKey('jwk',pair.publicKey);
  return {pair,id:b64(randomBytes(32)),userId,counter:0,cose:encodeCBOR(new Map([[1,2],[3,-7],[-1,1],[-2,new Uint8Array(Buffer.from(jwk.x,'base64url'))],[-3,new Uint8Array(Buffer.from(jwk.y,'base64url'))]]))};
}
function registration(key,options,customOrigin=origin){
  const id=Buffer.from(key.id,'base64url');const len=Buffer.alloc(2);len.writeUInt16BE(id.length);
  const authData=Buffer.concat([sha(hostname),Buffer.from([0x45]),Buffer.alloc(4),Buffer.alloc(16),len,id,Buffer.from(key.cose)]);
  const decoded=decodeCBOR(encodeCBOR(new Map([['authData',new Uint8Array(authData)]]))).get('authData');
  assert.equal(decoded.length,authData.length);assert.equal(new DataView(decoded.buffer,decoded.byteOffset).getUint16(53),id.length);
  decodeCBOR(decoded.slice(55+id.length));
  return {id:key.id,rawId:key.id,type:'public-key',clientExtensionResults:{credProps:{rk:true}},authenticatorAttachment:'platform',response:{
    clientDataJSON:b64(JSON.stringify({type:'webauthn.create',challenge:options.challenge,origin:customOrigin,crossOrigin:false})),
    attestationObject:b64(encodeCBOR(new Map([['fmt','none'],['attStmt',new Map()],['authData',new Uint8Array(authData)]]))),transports:['internal']}};
}
function derSignature(raw){
  const int=part=>{let bytes=Buffer.from(part);while(bytes.length>1&&bytes[0]===0)bytes=bytes.subarray(1);if(bytes[0]&0x80)bytes=Buffer.concat([Buffer.from([0]),bytes]);return Buffer.concat([Buffer.from([2,bytes.length]),bytes]);};
  const payload=Buffer.concat([int(raw.subarray(0,32)),int(raw.subarray(32))]);return Buffer.concat([Buffer.from([0x30,payload.length]),payload]);
}
async function assertion(key,options,{badSignature=false,badOrigin=false,userHandle=key.userId}={}){
  const clientData=Buffer.from(JSON.stringify({type:'webauthn.get',challenge:options.challenge,origin:badOrigin?'https://example.invalid':origin,crossOrigin:false}));
  const count=Buffer.alloc(4);count.writeUInt32BE(++key.counter);
  const authData=Buffer.concat([sha(hostname),Buffer.from([0x05]),count]);
  const raw=Buffer.from(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key.pair.privateKey,Buffer.concat([authData,sha(clientData)])));
  if(badSignature)raw[0]^=1;
  return {id:key.id,rawId:key.id,type:'public-key',clientExtensionResults:{},authenticatorAttachment:'platform',response:{clientDataJSON:b64(clientData),authenticatorData:b64(authData),signature:b64(derSignature(raw)),userHandle:b64(userHandle)}};
}
async function options(browser,path,data){const r=await browser.request(`/api/passkey/${path}/options`,'POST',data||{});check(r.status===200,`${path} options ${r.status}: ${JSON.stringify(r.body)}`);return r.body.options;}
async function login(browser,key,changes={}){const o=await options(browser,'login');const response=await assertion(key,o,changes);return {response,result:await browser.request('/api/passkey/login/verify','POST',{response})};}
async function signup(browser,name){const o=await options(browser,'register',{mode:'signup',displayName:name,keyName:'합성 테스트 키 1',storage:'기기 자체'});const key=await authenticator(Buffer.from(o.user.id,'base64url').toString());const response=registration(key,o);await verifyRegistrationResponse({response,expectedChallenge:o.challenge,expectedOrigin:origin,expectedRPID:hostname,requireUserVerification:true});const r=await browser.request('/api/passkey/register/verify','POST',{response});check(r.status===201,`signup verified: ${r.status} ${JSON.stringify(r.body)}`);return {key,user:r.body.user};}

const anonymous=new Browser(),a=new Browser(),b=new Browser(),cancelled=new Browser();
let r=await anonymous.request('/');check(r.status===200&&r.body.text.includes('함께할 땐 다정하게'),'public T01 preserved');
r=await anonymous.request('/private');check(r.status===200&&!r.body.text.includes('작은 전시 페이지 준비'),'private anonymous HTML has no note contents');
r=await anonymous.request('/api/private/notes');check(r.status===401,'anonymous notes 401');
check(r.headers.get('Cache-Control')==='no-store','private response no-store');
r=await anonymous.request('/api/passkey/keys');check(r.status===401,'anonymous key list 401');
r=await anonymous.request('/api/passkey/evidence');check(r.status===401,'anonymous key evidence 401');
r=await anonymous.request('/api/passkey/register/options','POST',{mode:'register',keyName:'bad',storage:'기기 자체'});check(r.status===401,'anonymous cannot add key to existing account');
r=await anonymous.request('/api/passkey/login/options','POST',{}, {Origin:'https://example.invalid'});check(r.status===403,'cross-site CSRF blocked');
r=await anonymous.request('/api/passkey/login/options','POST',{}, {'Content-Type':'text/plain'});check(r.status===415,'non-JSON blocked');
const cancelOptions=await options(cancelled,'register',{mode:'signup',displayName:'취소연습',keyName:'취소할 키',storage:'기기 자체'});
const cancelKey=await authenticator(Buffer.from(cancelOptions.user.id,'base64url').toString());
r=await cancelled.request('/api/passkey/cancel','POST',{});check(r.status===200,'cancellation accepted');
r=await cancelled.request('/api/passkey/register/verify','POST',{response:registration(cancelKey,cancelOptions)});check(r.status===400,'cancelled challenge cannot register');
r=await cancelled.request('/api/passkey/session');check(r.body.user===null,'cancelled registration no account session');
const A=await signup(a,'연습A'),B=await signup(b,'연습B');
r=await a.request('/api/private/notes');check(r.status===200&&r.body.notes.length===3,'A has three private notes');const aNotes=r.body.notes;
r=await b.request('/api/private/notes');check(r.status===200&&r.body.notes.length===3,'B has three private notes');const bNotes=r.body.notes;
check(aNotes.every(n=>n.body.includes('연습A'))&&bNotes.every(n=>n.body.includes('연습B')),'account contents differ');
r=await a.request('/api/passkey/evidence?userId='+B.user.id);check(r.status===200&&r.body.user.id===A.user.id&&r.body.keys.length===1&&r.body.keys[0].public_key,'public key evidence belongs to authenticated account');
r=await a.request('/api/private/notes/'+bNotes[0].id);check(r.status===403,'A to B forbidden');
r=await b.request('/api/private/notes/'+aNotes[0].id);check(r.status===403,'B to A forbidden');
r=await a.request('/api/private/notes?userId='+B.user.id);check(r.body.user.id===A.user.id&&r.body.notes.every(n=>n.body.includes('연습A')),'query user ID ignored');
r=await a.request('/api/private/notes','POST',{userId:B.user.id});check(r.body.user.id===A.user.id,'body user ID ignored');
for(const [browser,before] of [[a,aNotes],[b,bNotes]]){r=await browser.request('/api/private/notes');check(r.body.notes.length===before.length,'foreign attempts do not change record count');}
r=await a.request('/api/passkey/keys','DELETE',{id:B.key.id});check(r.status===403,'cannot delete other account key');
r=await a.request('/api/passkey/keys','DELETE',{id:A.key.id});check(r.status===409,'last key cannot be deleted');
r=await a.request('/api/passkey/keys');check(r.body.keys.length===1,'last key remains');
const addOptions=await options(a,'register',{mode:'register',keyName:'합성 테스트 키 2',storage:'보안 키'});
check(addOptions.excludeCredentials.some(k=>k.id===A.key.id),'existing credential excluded');
const A2=await authenticator(A.user.id);
r=await a.request('/api/passkey/register/verify','POST',{response:registration(A2,addOptions)});check(r.status===201,'second independent credential registered');
r=await a.request('/api/passkey/keys');check(r.body.keys.length===2&&r.body.keys.every(k=>k.name&&k.created_at),'two named dated keys');
const oldCookies=new Map(a.cookies);
r=await a.request('/api/passkey/logout','POST',{});check(r.status===200,'logout');
const stolen=new Browser();stolen.cookies=oldCookies;r=await stolen.request('/api/private/notes');check(r.status===401,'logged-out session reuse denied');
const o1=await options(a,'login'),o2=await options(a,'login');check(o1.challenge!==o2.challenge,'login challenges differ');
const good=await assertion(A.key,o2);r=await a.request('/api/passkey/login/verify','POST',{response:good});check(r.status===200,'valid signature accepted');
r=await a.request('/api/passkey/login/verify','POST',{response:good});check(r.status===400,'challenge replay denied');
r=(await login(a,A.key,{badSignature:true})).result;check(r.status===401,'tampered signature rejected');
r=(await login(a,A.key,{badOrigin:true})).result;check(r.status===401,'wrong WebAuthn origin rejected');
r=(await login(a,A.key,{userHandle:B.user.id})).result;check(r.status===401,'wrong user handle rejected');
const parallelOptions=await options(a,'login');const parallelResponse=await assertion(A.key,parallelOptions);
const concurrent=await Promise.all([a.request('/api/passkey/login/verify','POST',{response:parallelResponse}),a.request('/api/passkey/login/verify','POST',{response:parallelResponse})]);
check(concurrent.map(x=>x.status).sort().join(',')==='200,400','parallel challenge consumed only once');
const priorDeleteCookies=new Map(a.cookies);
r=await a.request('/api/passkey/keys','DELETE',{id:A.key.id});check(r.status===200&&r.body.signedOut,'delete key and sign out');
const stale=new Browser();stale.cookies=priorDeleteCookies;r=await stale.request('/api/private/notes');check(r.status===401,'deletion invalidates existing sessions');
r=(await login(a,A.key)).result;check(r.status===401,'deleted credential cannot log in');
r=(await login(a,A2)).result;check(r.status===200,'remaining credential can log in');
r=await a.request('/api/private/notes');check(r.status===200&&r.body.notes.length===3,'notes preserved after key removal');
const reg1=await options(a,'register',{mode:'register',keyName:'challenge 비교1',storage:'기기 자체'});
const reg2=await options(a,'register',{mode:'register',keyName:'challenge 비교2',storage:'기기 자체'});check(reg1.challenge!==reg2.challenge,'registration challenges differ');
await a.request('/api/passkey/cancel','POST',{});
r=await a.request('/api/passkey/logout','POST',{});check(r.status===200,'final logout A');
await b.request('/api/passkey/logout','POST',{});
mkdirSync('docs',{recursive:true});
writeFileSync('docs/ENGINEERING_EVIDENCE.json',JSON.stringify({testedAt:new Date().toISOString(),origin,scope:'Local D1, synthesized authenticators with real ECDSA signatures; no actual device registration',checks,users:[A.user,B.user],records:evidence},null,2));
writeFileSync('docs/ENGINEERING_TEST_RESULT.md',`# T08 자동 검증\n\n검증 시각: ${new Date().toISOString()}\n\n실제 HTTP와 로컬 D1을 대상으로 ${checks}개 확인을 통과했다. WebAuthn 형식의 합성 인증기가 실제 ECDSA 키와 서명을 만들어 검증했다. 이는 실제 기기 등록이나 사용자 생체 인증을 대신하지 않는다. 개인키는 실행 중 메모리에만 존재하고 기록·파일에 저장하지 않았다.\n\n확인: 공개 소개 보존, 미로그인 401, HTML에 메모 미포함, 계정 간 양방향 403, URL·본문 계정 ID 변조 시 본인 자료만 반환, 자료 건수 보존, 등록 취소, CSRF, 서명 변조, origin·userHandle 변조, challenge 재사용·동시 재사용, 로그아웃 세션 재사용, 서로 다른 패스키 두 개, 마지막 키 삭제 방지, 삭제 후 세션 무효화, 삭제한 키 실패와 남은 키 성공.\n\n요청·응답은 ENGINEERING_EVIDENCE.json에 있다. 쿠키는 가렸다. 아직 필요한 확인: 공개 운영 환경의 실제 패스키 등록·저장 위치, 기기 로그인, 실제 두 키 관리, 새 시크릿 창 공개 접근.\n`);
console.log(JSON.stringify({passed:checks,evidence:'docs/ENGINEERING_EVIDENCE.json',hardwareVerified:false}));
