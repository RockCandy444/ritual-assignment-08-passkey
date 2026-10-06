'use client';
import { useState } from 'react';
import { Music2, Languages, BookOpen, Gamepad2, ArrowUpRight, Heart, Users, Compass, Plus } from 'lucide-react';
import { Collapsible, CollapsibleTrigger, CollapsibleContent } from '@/components/ui/collapsible';
import { PasskeyPanel } from '@/components/passkey-panel';
const stories = [
  { n:'01', icon:Users, theme:'mint', tag:'함께하는 마음', title:'내 의견보다, 우리 사이', summary:'팀원들과 보조를 맞추며 마찰 없이 함께했습니다.', situation:'연수원에서 팀 프로젝트를 진행했습니다.', action:'제 의견만 밀고 가기보다 팀원들에게 맞추는 쪽을 선택했습니다.', result:'의견을 고집하며 부딪히는 일 없이 프로젝트에 참여했습니다.' },
  { n:'02', icon:Heart, theme:'peach', tag:'사람을 대하는 태도', title:'어려운 순간에도 친절하게', summary:'응대가 어려운 고객에게도 끝까지 친절을 지켰습니다.', situation:'아르바이트 중 응대가 어려운 고객을 만났습니다.', action:'상대의 태도에 휩쓸리지 않고 끝까지 친절하게 행동했습니다.', result:'응대를 마칠 때까지 친절한 태도를 유지했습니다.' },
  { n:'03', icon:Compass, theme:'lilac', tag:'끝까지 가는 호기심', title:'마지막 도전과제까지', summary:'게임 속 도전과제 100%를 향해 모험을 이어갔습니다.', situation:'게임을 하며 도전과제를 모두 달성하고 싶었습니다.', action:'중간에 접지 않고 마지막 도전과제까지 계속 도전했습니다.', result:'도전과제 100%를 달성할 때까지 플레이를 이어갔습니다.' },
];
export default function Home(){const [expanded,setExpanded] = useState<Record<string,boolean>>({}); return <>
<a className="skip" href="#main">본문으로 바로 가기</a>
<header className="top"><a className="wordmark" href="#main">솜사탕<span>의 작은 이야기</span><span className="dot" aria-hidden="true">●</span></a><nav aria-label="페이지 메뉴"><a href="#stories">나의 이야기</a><a href="#project">함께 만든 것 <ArrowUpRight size={16}/></a></nav></header>
<main id="main" tabIndex={-1}>
<section className="intro" aria-labelledby="intro-title"><div className="hello"><p className="eyebrow">반가워요, 제 이야기를 들려드릴게요.</p><h1 id="intro-title">함께할 땐 다정하게,<br/>좋아하는 건 <span>끝까지.</span></h1><p className="introduction">안녕하세요, <strong>솜사탕</strong>입니다.<br/>가족과 친구, 동료에게 제가 좋아하는 것과<br className="desktop-break"/> 경험 속에 담긴 제 모습을 소개합니다.</p></div>
<aside className="interests" aria-labelledby="interest-title"><div className="note-heading"><span className="small-label">조금 더 가까이</span><span aria-hidden="true">✳</span></div><h2 id="interest-title">나를 즐겁게 하는 것들</h2><ul><li><Music2/><span>악기 연주</span></li><li><Languages/><span>언어</span></li><li><BookOpen/><span>삼국지 · 일본 전국시대</span></li><li><Gamepad2/><span>게임</span></li></ul><p>음악부터 역사, 그리고 게임 속 모험까지.</p></aside></section>
<section id="stories" aria-labelledby="stories-title"><div className="section-heading"><h2 id="stories-title">경험 속의 나<span className="count">03</span></h2><p>작은 순간에 드러나는, 저다운 모습.</p></div><div className="stories-grid">{stories.map(s=><Collapsible key={s.n} open={!!expanded[s.n]} onOpenChange={(open)=>setExpanded(previous=>({...previous,[s.n]:open}))} className={`story ${s.theme}`}><div className="story-top"><s.icon size={22} aria-hidden="true"/><span>{s.n}</span></div><p className="tag">{s.tag}</p><h3>{s.title}</h3><p className="summary">{s.summary}</p><CollapsibleTrigger className="story-trigger" aria-label={`${s.title} — 이야기 ${expanded[s.n] ? "접기" : "펼쳐보기"}`}>{expanded[s.n] ? "이야기 접기" : "이야기 펼쳐보기"} <Plus size={18} aria-hidden="true"/></CollapsibleTrigger><CollapsibleContent className="story-content"><dl><dt>상황</dt><dd>{s.situation}</dd><dt>내가 한 행동</dt><dd>{s.action}</dd><dt>결과</dt><dd>{s.result}</dd></dl></CollapsibleContent></Collapsible>)}</div></section>
<section id="project" className="project" aria-labelledby="project-title"><div className="project-label"><span className="small-label">함께 만든 것</span><span className="role">백엔드 API 담당</span></div><div className="project-copy"><h2 id="project-title">공주시립합창단 홈페이지</h2><p>홈페이지 제작 프로젝트에서 백엔드 API를 담당했습니다.</p></div><a className="project-link" href="https://gongju.go.kr/gongjuchoir/" target="_blank" rel="noopener noreferrer">결과물 보러 가기 <ArrowUpRight size={19}/><span className="sr-only"> (새 탭)</span></a></section>
<PasskeyPanel />
</main><footer><p>솜사탕 <span>·</span> 저를 알아가는 작은 한 페이지</p><p>닉네임, 관심사, 직접 고른 경험만 담았습니다.</p></footer></>}

