import { PrivateRoom } from '@/components/private-room';
export default function PrivatePage() {
  return <><a className="skip" href="#main">본문으로 바로 가기</a><header className="top"><a className="wordmark" href="/">솜사탕<span>의 작은 이야기</span></a><nav aria-label="페이지 메뉴"><a href="/">공개 소개 보기</a></nav></header><PrivateRoom/><footer><p>솜사탕 · 나만의 메모함</p><p>실제 개인정보를 넣지 않는 연습용 공간입니다.</p></footer></>;
}
