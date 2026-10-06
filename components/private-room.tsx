'use client';
import { useEffect, useRef, useState } from 'react';
import { startRegistration, startAuthentication, browserSupportsWebAuthn, type PublicKeyCredentialCreationOptionsJSON, type PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser';
import { Fingerprint, KeyRound, LockKeyhole, LogOut, Plus, Trash2, NotebookPen } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { AlertDialog, AlertDialogContent, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogCancel, AlertDialogAction } from '@/components/ui/alert-dialog';

type User = {id:string;displayName:string};
type Note = {id:string;category:string;title:string;body:string;updated_at:number};
type Key = {id:string;name:string;storage:string;created_at:number;device_type:string;backed_up:number};
const stores = ['기기 자체', '구글 비밀번호 관리자', '보안 키', '다른 비밀번호 관리자'];
// Evidence is intentionally scoped to this browser page lifetime, never auth state.
const requestHistory:unknown[]=[];
let historyOwnerId:string|null=null;
async function api<T=Record<string,unknown>>(path:string, method='GET', value?:unknown):Promise<T> {
  if(path==='/api/passkey/register/options' && (value as {mode?:string})?.mode==='signup') {requestHistory.length=0;historyOwnerId=null;}
  const response=await fetch(path,{method,credentials:'same-origin',cache:'no-store',
    ...(method!=='GET' ? {headers:{'Content-Type':'application/json'},body:JSON.stringify(value || {})} : {})});
  const result=await response.json() as {message?:string} & T;
  const responseOwner=(result as {user?:{id?:string}}).user?.id;
  if(responseOwner) {
    if(historyOwnerId && historyOwnerId!==responseOwner) {
      const pending=requestHistory.slice(-1).filter(record=>(record as {request?:{path?:string}}).request?.path==='/api/passkey/login/options');
      requestHistory.length=0;requestHistory.push(...pending);
    }
    historyOwnerId=responseOwner;
  }
  if(path!=='/api/passkey/evidence' && path!=='/api/passkey/session') {
    requestHistory.push({at:new Date().toISOString(),request:{method,path,body:value??null,cookie:'[REDACTED]'},response:{status:response.status,body:result}});
    if(requestHistory.length>100)requestHistory.shift();
  }
  if(!response.ok) throw new Error(result.message || '요청을 처리하지 못했어요.');
  return result;
}
function date(value:number) { return new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',year:'numeric',month:'long',day:'numeric'}).format(value); }

export function PrivateRoom() {
  const [user,setUser]=useState<User|null>(null), [notes,setNotes]=useState<Note[]>([]), [keys,setKeys]=useState<Key[]>([]);
  const [loading,setLoading]=useState(true), [busy,setBusy]=useState(false), [supported,setSupported]=useState(false);
  const [signup,setSignup]=useState(false), [displayName,setDisplayName]=useState('솜사탕');
  const [keyName,setKeyName]=useState('내 컴퓨터'), [storage,setStorage]=useState('기기 자체');
  const [message,setMessage]=useState(''), [error,setError]=useState(false), [deleting,setDeleting]=useState<Key|null>(null);
  const stateRef=useRef({locked:true,passkeyCount:0});
  stateRef.current={locked:!user,passkeyCount:keys.length};
  async function refresh() {
    const current=await api<{user:User|null}>('/api/passkey/session');
    if(!current.user){setUser(null);setNotes([]);setKeys([]);return;}
    const [privateData,keyData]=await Promise.all([api<{notes:Note[]}>('/api/private/notes'),api<{keys:Key[]}>('/api/passkey/keys')]);
    setUser(current.user);setNotes(privateData.notes);setKeys(keyData.keys);
  }
  useEffect(()=>{
    setSupported(window.isSecureContext && browserSupportsWebAuthn());
    refresh().catch(()=>{setError(true);setMessage('메모함을 불러오지 못했어요. 잠시 후 새로고침해 주세요.');}).finally(()=>setLoading(false));
    // Recheck an expired/revoked session when the visitor returns to this tab.
    const onFocus=()=>refresh().catch(()=>{setUser(null);setNotes([]);setKeys([]);});
    window.addEventListener('focus',onFocus);
    const timer=window.setInterval(onFocus,60000);
    type ToolContext={registerTool:(tool:unknown,options?:{signal:AbortSignal})=>unknown};
    const context=(document as Document & {modelContext?:ToolContext}).modelContext;
    const lifecycle=new AbortController();
    if(context?.registerTool) {
      try { Promise.resolve(context.registerTool({name:'read_memo_room_status',title:'메모함 잠금 상태 확인',
        description:'현재 화면의 잠금 상태와 등록된 패스키 개수만 확인합니다. 메모 내용과 인증값은 반환하지 않습니다.',
        inputSchema:{type:'object',properties:{},additionalProperties:false},annotations:{readOnlyHint:true,untrustedContentHint:false},
        execute(input:unknown){if(!input || typeof input!=='object' || Array.isArray(input) || Object.keys(input).length)throw new Error('빈 객체만 입력할 수 있습니다.');return {...stateRef.current};}}, {signal:lifecycle.signal})).catch(()=>{}); }catch{}
    }
    return ()=>{window.removeEventListener('focus',onFocus);window.clearInterval(timer);lifecycle.abort();};
  // Account data is loaded only after mount; it never enters anonymous HTML/RSC.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  },[]);
  async function run(operation:()=>Promise<void>) {
    if(busy)return;setBusy(true);setError(false);setMessage('');
    try { await operation(); }
    catch(e){setError(true);setMessage(e instanceof Error ? e.message : '다시 시도해 주세요.');}
    finally {setBusy(false);}
  }
  async function register(mode:'signup'|'register') {
    await run(async()=>{
      const {options}=await api<{options:PublicKeyCredentialCreationOptionsJSON}>('/api/passkey/register/options','POST',{mode,displayName,keyName,storage});
      let response;
      try { response=await startRegistration({optionsJSON:options}); }
      catch(e){await api('/api/passkey/cancel','POST').catch(()=>{});
        if(e instanceof Error && ['NotAllowedError','AbortError'].includes(e.name))throw new Error('등록을 취소했거나 시간이 지났어요. 계정과 패스키는 저장되지 않았어요.');
        throw new Error('패스키를 만들지 못했어요. 다른 저장 위치를 선택하거나 패스키를 지원하는 브라우저에서 시도해 주세요.');}
      await api('/api/passkey/register/verify','POST',{response});await refresh();setSignup(false);setKeyName('추가 패스키');setMessage('패스키를 등록했어요. 실제로 선택한 저장 위치가 맞는지 목록에서 확인해 주세요.');
    });
  }
  async function login() {
    await run(async()=>{
      const {options}=await api<{options:PublicKeyCredentialRequestOptionsJSON}>('/api/passkey/login/options','POST');
      let response;
      try {response=await startAuthentication({optionsJSON:options});}
      catch{await api('/api/passkey/cancel','POST').catch(()=>{});throw new Error('로그인을 완료하지 못했어요. 등록한 패스키를 선택해서 다시 시도해 주세요.');}
      await api('/api/passkey/login/verify','POST',{response});await refresh();setMessage('메모함을 열었어요.');
    });
  }
  async function logout() {
    await run(async()=>{await api('/api/passkey/logout','POST');setUser(null);setNotes([]);setKeys([]);setSignup(false);setMessage('메모함을 잠갔어요.');});
  }
  async function remove(key:Key) {
    setDeleting(null);
    await run(async()=>{await api('/api/passkey/keys','DELETE',{id:key.id});setUser(null);setNotes([]);setKeys([]);setMessage('패스키를 삭제하고 메모함을 잠갔어요. 남은 패스키로 다시 열어 주세요.');});
  }
  async function exportEvidence() {
    await run(async()=>{
      const server=await api('/api/passkey/evidence');
      const blob=new Blob([JSON.stringify({scope:'Actual requests from this browser page only; device/provider must be confirmed by the user',server,requests:requestHistory,sessionValuesIncluded:false},null,2)],{type:'application/json'});
      const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=`t08-passkey-check-${new Date().toISOString().slice(0,10)}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
      setMessage('확인 기록을 저장했어요. 실제 저장 위치와 패스키 목록 화면도 함께 확인해 주세요.');
    });
  }
  const registrationForm=(mode:'signup'|'register')=><form className="key-form" onSubmit={e=>{e.preventDefault();void register(mode);}}>
    {mode==='signup' && <label htmlFor="nickname">메모함 별명<input id="nickname" value={displayName} onChange={e=>setDisplayName(e.target.value)} required maxLength={30} autoComplete="off"/><span>실명이나 연락처 대신 별명을 써 주세요.</span></label>}
    <label htmlFor="key-name">패스키 이름<input id="key-name" value={keyName} onChange={e=>setKeyName(e.target.value)} required maxLength={50} autoComplete="off"/></label>
    <div className="store-field"><label htmlFor="key-store">저장할 곳</label><Select value={storage} onValueChange={setStorage}><SelectTrigger id="key-store" className="store-trigger"><SelectValue/></SelectTrigger><SelectContent className="store-menu">{stores.map(s=><SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent></Select><p>다음 패스키 창에서 실제로 선택한 위치와 맞춰 주세요.</p></div>
    <button className="vault-button" type="submit" disabled={busy || !supported}><Plus size={18}/>{busy?'확인 중…':mode==='signup'?'패스키로 메모함 만들기':'패스키 추가하기'}</button>
  </form>;
  return <main className="private-page" id="main" tabIndex={-1}>
    <div className="room-heading"><div><p className="small-label"><LockKeyhole size={16}/> 나만 보는 자리</p><h1>나만의 메모함</h1></div><span className={`lock-badge ${user?'open':''}`}>{loading?'확인 중':user?'열림':'잠김'}</span></div>
    {message && <p className={`room-message ${error?'error':''}`} role={error?'alert':'status'}>{message}</p>}
    {loading?<div className="locked-room" aria-busy="true"><p>메모함 상태를 확인하고 있어요.</p></div>:!user?<div className="locked-room">
      <Fingerprint size={42} strokeWidth={1.5} aria-hidden="true"/><h2>등록한 패스키로 열어 주세요.</h2><p>공개 소개는 누구나 볼 수 있어요.<br/>이 안의 메모는 내 패스키로만 열립니다.</p>
      {!supported && <p className="room-message error">이 브라우저에서는 패스키를 사용할 수 없어요. 최신 Chrome·Edge·Safari와 HTTPS 주소에서 열어 주세요.</p>}
      <button className="vault-button" disabled={busy || !supported} onClick={()=>void login()}><Fingerprint size={20}/>{busy?'확인 중…':'패스키로 열기'}</button>
      <button className="room-link" disabled={busy} onClick={()=>{setSignup(!signup);setMessage('');}} aria-expanded={signup}>{signup?'등록 닫기':'처음이에요 · 메모함 만들기'}</button>
      {signup && <div className="signup-box"><h3>별명과 패스키로 시작해요.</h3><p>새 메모함에 가상의 연습 메모 세 개를 넣어 드려요.</p>{registrationForm('signup')}</div>}
    </div>:<>
      <div className="owner-bar"><div><h2>{user.displayName}의 메모</h2><p>아래 내용은 모두 만들어 넣은 연습용 메모입니다.</p></div><button className="room-outline" onClick={()=>void logout()} disabled={busy}><LogOut size={17}/>메모함 잠그기</button></div>
      <div className="notes-grid">{notes.map((note,i)=><article className={`private-note note-${i}`} key={note.id}><p className="note-category"><NotebookPen size={17}/>{note.category}</p><h3>{note.title}</h3><p>{note.body}</p><span className="note-date">{date(note.updated_at)}</span></article>)}</div>
      <section className="key-management" aria-labelledby="keys-title"><div className="section-heading"><h2 id="keys-title"><KeyRound size={22}/> 내 패스키 <span className="count">{keys.length}개</span></h2></div><p>이름과 등록 날짜로 구분해요. 예비 패스키는 다른 저장 위치에 만들어 두세요.</p>
        <ul className="key-list">{keys.map(key=><li key={key.id}><KeyRound size={20} aria-hidden="true"/><div><strong>{key.name}</strong><p>{key.storage} · {date(key.created_at)}</p><span>{key.device_type==='multiDevice'?'동기화형 패스키':'기기 기반 패스키'} · 저장 위치는 직접 선택한 기록</span></div><button className="delete-key" aria-label={`${key.name} 패스키 삭제`} onClick={()=>setDeleting(key)} disabled={busy || keys.length===1}><Trash2 size={17}/>삭제</button></li>)}</ul>
        {keys.length===1 && <p className="key-hint">패스키가 하나예요. 다른 저장 위치에 하나 더 등록하면 분실에 대비할 수 있어요.</p>}
        <div className="add-key"><h3>예비 패스키 추가</h3>{registrationForm('register')}</div>
        <div className="evidence-export"><button className="room-outline" disabled={busy} onClick={()=>void exportEvidence()}>확인 기록 내려받기</button><p>이 브라우저에서 진행한 등록·로그인 요청과 서버의 공개키를 저장해요. 로그인 값은 포함하지 않습니다. 새로고침하면 이 브라우저의 요청 기록은 초기화됩니다.</p></div>
      </section>
    </>}
    <aside className="recovery-note"><h3>패스키를 모두 잃어버렸다면</h3><p>이 메모함은 비밀번호나 이메일로 복구할 수 없어요. 사용할 수 있는 패스키가 하나도 없으면 기존 메모함에 다시 들어갈 수 없습니다. 그때는 새 메모함을 만들어야 해요.</p><p>마지막 패스키는 삭제할 수 없어요. 다른 패스키를 먼저 추가해 주세요. 동기화된 같은 패스키가 두 기기에 보이는 것은 예비 패스키 두 개를 등록한 것과 다를 수 있어요.</p></aside>
    <AlertDialog open={!!deleting} onOpenChange={open=>{if(!open)setDeleting(null);}}><AlertDialogContent className="delete-dialog"><AlertDialogTitle>이 패스키를 삭제할까요?</AlertDialogTitle><AlertDialogDescription>‘{deleting?.name}’으로는 더 이상 로그인할 수 없어요. 메모함이 잠기며, 남은 패스키로 다시 로그인해야 합니다.</AlertDialogDescription><AlertDialogFooter><AlertDialogCancel>취소</AlertDialogCancel><AlertDialogAction className="confirm-delete" onClick={()=>{if(deleting)void remove(deleting);}}>삭제하고 잠그기</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </main>;
}
