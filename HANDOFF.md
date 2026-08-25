# Nullify — 인수인계 (새 대화창용)

이 파일 하나로 이전 대화의 전체 맥락을 복원한다. 새 세션은 먼저 이걸 읽고 이어서 진행할 것.

## 0. 새 세션이 가장 먼저 할 일
1. 이 파일 정독.
2. 서버 재기동:  `cd C:\Users\ansih\nullify && python web.py`  → http://127.0.0.1:8000
3. 자가진단:  `python selftest.py`  (전부 PASS 여야 정상)
4. 사용자는 정보보호학과 1학년(한국어). 코드엔 왜 그렇게 짰는지 한 줄 설명, 처음 나오는 도구는 한 문장 짚기, 확신 없으면 없다고 말하기. (전역 CLAUDE.md에 있음)

## 1. Nullify 가 뭔가
2026 UNITHON 해커톤 출품작. 주제 **[UNWORK] 일을 지우고 사람을 남기다**.
컨셉: **보안 스캐너가 쏟아내는 오탐 검수 노동을 없앤다.**
- 스캐너(Nuclei/Semgrep)를 입구로 받아 → **결정론적으로 실제 찔러보고**(LLM 없이) → 진짜 터지는 것만 골라 →
  고치고 → **재검증(같은 공격 재실행)으로 죽었음을 증명(영수증)** → 이력·추세 추적.
- 차별점: 검증에 LLM 안 씀(환각 방지). LLM 은 '수정 생성'에만. Copilot Autofix 는 정적 추론까지만, 우리는 런타임 증거.

## 2. 핵심 설계 원칙 (절대 지킬 것)
- **검증(verification)=결정론.** 참/거짓 응답 차분, 실제 exploit 재현으로 판정. LLM 금지.
- **LLM 은 수정 생성에만.** `fixgen.py`, 키(`ANTHROPIC_API_KEY`) 있을 때만. 키는 코드가 읽기만, 절대 안 다룸.
- **엔진은 과녁을 import 안 함.** HTTP 로만 대화(진짜 외부 스캐너). 데모 과녁은 별도 프로세스로 spawn.
- **취약점 주장은 파일:라인 + 트리거 입력으로.** 추측은 추측이라 라벨.
- **권한 게이트**: 공개 URL 은 거부(로컬/사설망·소유권 증명만 허용). 남의 사이트 스캔 금지.
- **3-way 랭킹**: critical(지금 진짜 터짐) / question(질문하면 확정=IDOR) / warn(설정·버전) / info(오탐·안전).

## 3. 파이프라인
```
① 입력   DAST: URL(Nuclei/직접찌름)   SAST: repo(Semgrep/시크릿스캔)
② 수집   scanner_report.jsonl(샘플) → ingest.py 어댑터 → 후보
③ 검증   verify_*.py 10종, 결정론, 실제 찔러봄 (제품의 심장)
   공격  exploit_sqli.py (UNION 탈취 등)
④ 고침   fixes.py 카탈로그 → 없으면 fixgen.py(LLM) → 없으면 검토필요
⑤ 재검증 control(HTTP)로 패치배포→재실행→죽음확인
⑥ 영수증 before→after, github_pr.py 로 실제 git 브랜치·커밋(push만 사용자 몫)
결합   combine.py: DAST+SAST 상관 → 증거등급(정적+동적/동적/정적만)
```

## 4. 파일 지도 (C:\Users\ansih\nullify, 파이썬 ~25개 ·약 3천줄)
- **web.py** (~760줄) — 엔진: 다중페이지 UI(사이드바 네비) + 모든 API. 여기가 오케스트레이터.
- **vuln_app.py** (431줄) — 일부러 취약한 데모 과녁(별도 프로세스). `/control` 로 패치배포 토글. 실제 제품 아님.
- **verify_sqli/xss/idor/traversal/cmdi/redirect/ssrf/headers/secret/component.py** — 검증기 10종(결정론).
- **exploit_sqli.py** — UNION 컬럼수탐지+데이터탈취.
- **fixes.py** — 취약점별 수정 카탈로그(before→after). **github_pr.py** — 실제 git 브랜치/커밋/clone(`connect_repo`), `create_fix`.
- **fixgen.py** — LLM 수정 생성(Anthropic Messages API, `claude-sonnet-5` 기본). 키 없으면 검토필요 폴백.
- **ingest.py** — Nuclei JSONL→후보 어댑터. **scanner.py** — 실 Nuclei 실행/내장 discovery/샘플 폴백.
- **discover.py** — 후보 자동발견(임의앱 대응). 외부 스캐너 없이 대상 앱을 직접 훑음: (A)크롤 `<a>/<form>/<script>` same-origin BFS, (B)탐침 흔한 경로+파라미터 소사전. 파라미터명→kind 추정, 헛후보는 검증기가 거름. stdlib(html.parser)만. `NULLIFY_DISCOVER=1` 또는 API `?discover=1`(UI 체크박스)로 켬.
- **sast.py** — Semgrep 실행/시크릿스캔 폴백. **scan_source.py** — 소스 시크릿 정규식 스캐너.
- **combine.py** — DAST+SAST 상관·증거등급.
- **authorize.py** — 권한 게이트. **store.py** — SQLite: 스캔·이력·알림 + **사용자 계정(멀티테넌시, 토큰 SHA-256)**.
- **notify.py** — 리그레션 알림(로컬로그 + `NULLIFY_WEBHOOK` 선택). **nullify_ci.py** — CI 보안 게이트(exit 1=실패).
- **selftest.py** — 검증기 자가진단(전부 PASS 확인용).
- **Dockerfile**, **DEPLOY.md**(로드맵), **.github/workflows/nullify.yml**(CI), **scanner_report.jsonl**(샘플).
- **sample_repo/** — 수정 PR 데모용 git 레포(자동 생성). **nullify.db** — SQLite(자동 생성, 지워도 됨).

## 5. 지금 되는 것 / 안 되는 것 (정직하게)
**됨(검증됨):** 검증기 10종, 공격재현, 3-way 랭킹, IDOR 질문→확정, 닫힌루프 영수증, 실제 git 수정·PR(로컬까지),
스캐너 어댑터, 상태저장·이력, 재검증 추적, 알림, 인증(엔진+UI)·요청제한, 멀티테넌시, CI 게이트, SAST 어댑터, DAST+SAST 결합, 다중페이지 UI.
**데모 스캐폴드(의도됨):** vuln_app(토이 과녁), scanner_report.jsonl(샘플), 검증기가 표준 param(id/q/file...) 가정.
**안 됨/외부의존:** 실 Nuclei·Semgrep·LLM·GitHub push 는 설치·키·토큰 필요(사용자 몫, 코드는 표준). 소스위치→런타임트리거 자동변환 불가(그래서 combine 은 kind 로 상관). 셀프 회원가입 UI 없음(CLI 발급).
**임의앱 대응(2026-08-25 추가):** discover.py 로 외부 스캐너 없이 후보 자동발견 → 토이 앱 9종 엔드포인트 전부 재발견, 크롤은 합성 링크/폼도 추출(same-origin 강제). 크롤 깊이·페이지는 `NULLIFY_CRAWL_DEPTH/PAGES` 로 튜닝. **이 작업 중 verify_ssrf 오탐 버그 발견·수정**: 검증기가 302 자동추적해 오픈리다이렉트를 SSRF 로 오판 → 리다이렉트 미추적으로 고침(selftest 회귀 가드 `SSRF≠Redirect 구분`).
**IDOR 임의경로 일반화(2026-08-25 추가):** verify_idor.enumerate_test — 인증 없이 관찰 가능한 IDOR 신호=객체열거. `/path?id=N` 옆 `id=N±1` 이 접근제어 없이 다른 실 객체를 200 으로 주면 UNKNOWN(질문)→owner_only 답 시 CONFIRMED. 오탐방지: 에러표식·동일내용·길이비 0.3~3x 밖은 제외(접근제어 403/정적페이지는 안 잡힘 — 테스트 확인). scan_idor(base,path,param): `/order` 는 기존 토이 교차계정(닫힌루프까지), 그 외는 열거. **한계**: 제네릭 IDOR 는 재검증(패치 후 죽음 증명)에 인증/소유권 컨텍스트 필요 → receipt 에 `fixed:False`+note 로 정직하게 미검증 표시. 인증 뒤 페이지·JS 렌더 SPA 는 크롤 못 감(정적 HTML만).

## 6. 환경 함정 (시간 낭비 방지)
- Windows + Python 3.14. **콘솔 cp949** → 한글 깨져 보임(실제 UTF-8 정상). 실행 시 `PYTHONUTF8=1 PYTHONIOENCODING=utf-8` 붙이면 덜 깨짐.
- **docker·nuclei·semgrep·gh 미설치.** node 는 있음(v24). git 있음(2.54).
- **`python web.py &` (인라인 &)는 Bash 도구를 파이프로 잡아 2분 타임아웃** 발생 → 서버는 정상. 백그라운드로 띄우려면 Bash `run_in_background:true` 사용.
- 서버 재기동: `taskkill //F //IM python.exe` 로 이전 것 죽이고 다시. (web.py 가 8009 과녁도 자동 spawn)
- web.py 는 표준 라이브러리만. UI 는 web.py 안 PAGE 문자열(다중뷰 SPA, 해시 라우팅).

## 7. 인증/설정 환경변수
`NULLIFY_API_TOKEN`(엔진 토큰), `NULLIFY_TARGET`(외부 대상), `NULLIFY_USE_NUCLEI=1`, `NULLIFY_HOST/PORT/RATE_MAX`,
`NULLIFY_WEBHOOK`(알림), `ANTHROPIC_API_KEY`+`NULLIFY_FIX_MODEL`(LLM 수정). 계정: `python store.py adduser <이름>`.

## 8. 실전 검증 사례
사용자 실제 레포 **github.com/ansihoo/PageMate**(공동 PDF 학습 Node 앱) 점검:
- Nullify 자동: 시크릿 깨끗, **보안헤더 누락 CONFIRMED**(X-Frame-Options·CSP).
- 수동 코드리뷰로 발견: **저장형 XSS 진짜** — `server.js` /api/annotations/sync 가 `{...item}` 스프레드로 `ownerColor`·`createdAt` 무새니타이즈 → `app.js:653` innerHTML 렌더. 트리거: sync 에 ownerColor 로 HTML 주입 → 방 전원 XSS. (Semgrep 붙이면 자동 탐지될 것)
- 교훈: 자동도구는 헤더만, 심각한 XSS 는 SAST/수동 필요 → 그래서 SAST+DAST+검증 다 필요.

## 9. 대회 점수 현황 (레버리지)
- 기술·시제품(300) 🟢 매우 강함 / 문제해결논리(150) 🟢 / 주제적합(100) 🟢
- 서비스기획·UX(100) 🟡 UI 이제 다중페이지로 개선함 / 발표(100) 🟡 미작성
- **사업역량(250: 시장·경쟁·BM·전략) 🔴 문서 전무 = 최대 공백.**
- 사용자는 "문서화는 아직 시간 많아 나중" 입장 → 당분간 배포/기능 계속.

## 10. 다음 후보 (사용자가 고르게)
- ✅ 임의앱 대응(후보 자동발견) — discover.py 완료(2026-08-25). ✅ IDOR 임의경로 일반화(enumerate_test) 완료. ✅ 크롤 깊이 env 튜닝. 남은 후속: 폼 **POST** 파라미터 실검증(현재 검증기 전부 GET 전용 — POST 지원하려면 검증기 10종 손봐야, 큰 작업), 제네릭 IDOR 닫힌루프(인증 컨텍스트 주입 방식 설계 필요).
- UI 더 다듬기(결과카드·로딩·빈상태), Semgrep/Nuclei 실설치 데모(사용자), OAuth 레포연결(구조만),
  알림 채널 확장, 또는 문서화 전환.
- 지금까지 "순수 코드로 리스크 없이 배포 근접"은 거의 소진. 남은 큰 건 외부 서비스 실연동(사용자 계정·키 필요).
