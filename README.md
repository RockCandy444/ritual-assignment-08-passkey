# 솜사탕의 작은 이야기 · 패스키 메모함 (T08)

T01 공개 소개를 이어받아 패스키로 보호하는 가상 메모함을 추가했다. 비밀번호·이메일 가입 없이 별명과 패스키로 새 계정을 만들고, 모든 메모는 로그인한 계정에서만 서버가 조회한다.

구현: 등록, 추가 등록, 로그인, 로그아웃, 계정별 가상 메모 3개, 키 목록·삭제, 마지막 키 보호, 5분 일회 challenge, 12시간 서버 세션, CSRF 방어. 서명 검증은 SimpleWebAuthn을 사용한다.

## 실행

Node 22.13 이상에서 `npm run install:ci`, `npm run dev -- --port 5178`로 실행한다. D1 마이그레이션 적용은 starter의 로컬 실행 절차를 따른다. `npm run build`는 Sites Worker를 생성한다. 논리 DB 이름은 `DB`이다.

`node scripts/check-passkey.mjs`는 로컬 앱·D1에 합성 인증기의 실제 ECDSA 요청을 보내 인증·권한 검증을 수행한다. `node scripts/export-test-public-keys.mjs`는 해당 테스트 계정의 공개키만 읽어 증거에 저장한다. 합성 개인키는 실행 중 메모리에만 있으며 파일로 저장하지 않는다.

## 확인·제출 자료

- `docs/T08_AUTH_EXPLANATION.md`: 설명서 6항목, 소스 흐름, 한계.
- `docs/ENGINEERING_TEST_RESULT.md`, `docs/ENGINEERING_EVIDENCE.json`: 자동 검증 결과와 가려진 요청·응답.
- `docs/TEST_PUBLIC_KEYS.json`: 테스트에서 서버에 저장된 공개키.
- `docs/DEVICE_CHECK_GUIDE.md`: Windows PC + 스마트폰 실제 확인.
- `docs/T08_REQUIREMENTS.md`: 안내 카드별 상태.

실제 기기 확인 전에는 과제 완료로 표시하지 않는다. 모든 비공개 메모는 만들어 넣은 가상 내용이다. 실제 개인정보를 저장하는 서비스로 사용하지 않는다.
