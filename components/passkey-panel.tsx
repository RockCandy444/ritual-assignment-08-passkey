import { Fingerprint, LockKeyhole } from 'lucide-react';

export function PasskeyPanel() {
  return <section className="vault-entry" id="private" aria-labelledby="vault-title">
    <div><p className="small-label"><LockKeyhole size={16} aria-hidden="true"/> 나만 보는 자리</p><h2 id="vault-title">나만의 메모함</h2><p>준비 중인 생각과 연습 기록은 이 안에 담아요.</p></div>
    <div className="vault-entry-actions"><a className="vault-button" href="/private"><Fingerprint size={20} aria-hidden="true"/> 패스키로 열기</a><p>비밀번호 없이, 등록한 패스키로만 열립니다.</p></div>
  </section>;
}
