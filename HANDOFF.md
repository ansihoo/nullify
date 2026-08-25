# Nullify — 인수인계 (새 대화창용)

이 파일 하나로 이전 대화의 전체 맥락을 복원한다. 새 세션은 먼저 이걸 읽고 이어서 진행할 것.

## 0. 새 세션이 가장 먼저 할 일
1. 이 파일 정독.
2. 서버 재기동:  `cd C:\Users\ansih\nullify && python web.py`  → http://127.0.0.1:8000
3. 자가진단:  `python selftest.py`  (전부 PASS 여야 정상)
4. 사용자는 정보보호학과 1학년(한국어). 코드엔 왜 그렇게 짰는지 한 줄 설명, 처음 나오는 도구는 한 문장 짚기, 확신 없으면 없다고 말하기. (전역 CLAUDE.md에 있음)

## 0.5. ⭐ 최신 상태 (2026-08-26) — 새 세션은 여기부터 (아래 원본은 초기 백엔드 맥락)
프로젝트가 **이름 VibeShield**(구 Nullify)로 바뀌었고, **React 프론트 + LLM 챗 + 자동수정**까지 붙었다.

**실행법 (두 서버):**
- 백엔드: `cd C:\Users\ansih\nullify && python web.py` → :8000 (과녁 :8009 자동)
- 프론트: `cd C:\Users\ansih\nullify\unknown-security-scanner && npm run dev` → :3000
- **LLM 챗**: `unknown-security-scanner/.env` 에 `GEMINI_API_KEY=...` (gitignore됨, 커밋 금지). 없으면 폴백 설명으로 동작.
- 자가진단: `python selftest.py` (전부 PASS)

**폴더 구조 리팩터됨**: `verifiers/`(검증기10+exploit), `discovery/`(scanner/discover/ingest/sast/scan_source), `remediation/`(fixes/fixgen/github_pr), `infra/`(store/authorize/notify). 루트엔 web.py·vuln_app.py·combine.py·selftest.py 등.

**프론트 (`unknown-security-scanner/`, React+Vite+TS, AI Studio 목업 개조):**
- 입력: 사이트 URL + GitHub 레포(선택) 동시. **URL만=탐지전용(수정X)** / 레포=SAST / 둘다=완전체(수정O).
- 흐름: 스캔→분석→수정→검증(상단 스텝퍼). 좌측=스캔 히스토리(localStorage, ChatGPT식, 삭제/복원). 0건이면 전용 '클린' 화면.
- 어댑터 `src/api/nullify.ts`: 백엔드 findings→Vulnerability. scanEntry/generateFix/resolveIntent/rescanTarget. `_raw/_source/_isRepo/_canFix` 숨김 필드로 백엔드 재호출.
- 검증뷰: '수정됨(커밋)' vs '증명완료(재검증으로 죽음확인, receipt.afterResponse.vulnerable===false)' 구분. 24h 쿨타임 자동재검증 + 수동 '지금 재검증'.
- 설정: 자동재검증 on/off, 노이즈필터(strict/all) 실연동. 웹훅은 '준비중'(미연동).
- LLM 챗(Gemini): 범용 도우미(취약점 강제 안 함). **검증엔 LLM 안 씀 원칙 유지** — 챗/수정생성만.

**자동수정 (remediation/github_pr.py):**
- `create_fix(repo,kind)`: kind=='headers'→`create_headers_fix`(express=미들웨어 주입 / netlify=_headers / **Vercel=vercel.json**), kind=='secret'→`create_secret_fix`(하드코딩 AKIA 키 소스에서 제거). 그 외 코드계열→카탈로그→**fixgen(Gemini로 전환됨)**→검토.
- 데모(토이/sample_repo)는 실제 커밋+닫힌루프 완성. 임의 레포는 headers/secret 실동작 + 코드계열은 fixgen(Gemini).

**발표 데모 세팅:** 팀원 제작 외부 취약 타깃 `case-intake-pro-vuln-target.vercel.app`(+레포 `github.com/smartharry1014/case-intake-pro-vuln-target`), allowlist 등록됨. 취약점=**시크릿 노출(크리티컬, lovable-error-reporting.ts:29의 AKIA)** + 헤더누락. 데모 흐름: 스캔(URL+레포)→분석→**시크릿 패치생성(키 제거 커밋)**→cmd `git push`→**Vercel 자동배포(~30-60s)**→재검증→크리티컬 죽음확인.
- ⚠️ 데모 전 확인: 그 레포 push 권한 + Vercel auto-deploy 연결 여부. 배포 지연 감안. 노출된 실키면 폐기(rotate).
- 안전판: 토이앱(127.0.0.1:8009)은 "고친 상태로 배포(데모)" 컨트롤로 배포 지연·인증 없이 100% 재현(검증됨: sqli 배포→재검증 crit 7→6, CONFIRMED→FALSE_POSITIVE).

**사업 브리프**: `scratchpad/VibeShield_사업브리프.md` 만들어둠(사업계획서용, 시장·BM·경쟁·리스크). 시장숫자·단가는 대략치라 최신 출처 검증 필요.

**협업**: 공동개발자 `YoonSeongJune02`/`smartharry1014`가 병렬로 계속 push함(삭제메뉴·git복사·fixgen Gemini·데모타깃 등). **매번 `git fetch` 후 병합할 것.** 레포 `ansihoo/nullify`(비공개).

**정직한 한계(계획서·발표용)**: 킬러 데모를 토이 밖에서 완전 증명은 진행중. 실 Nuclei/Semgrep 미설치. git push≠라이브 재배포(재검증 clean은 실제 배포 후에만). 검증 파이프라인이 증명 위해 실데이터 추출→DB/localStorage 저장(호스티드 가면 PII 부담; canary/마스킹 미구현). 제네릭 IDOR 닫힌루프 미완.

---

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
- ✅ 임의앱 대응(후보 자동발견) — discover.py 완료(2026-08-25). ✅ IDOR 임의경로 일반화(enumerate_test) 완료. ✅ 크롤 깊이 env 튜닝.
- ✅ **폼 POST 파라미터 실검증 완결(2026-08-25)** — 동료(YoonSeongJune02)가 verify_sqli/xss/cmdi/traversal 에 `method="GET"|"POST"` 추가 + vuln_app do_POST(`_dispatch` 분리). 이어서 배선 완료: discover 가 `<form method=post>` 인식해 후보에 `method` 실어보냄(dedup 키에 method 포함), web.py scan_* 4종·SCANNERS·run_scan 이 method 관통, exploit_sqli(find_column_count/union_extract)도 method 받아 POST 탈취까지. GET 기본값이라 하위호환. selftest 가드: 공격재현 POST·discover 폼 POST 인식.
- 남은 후속: 제네릭 IDOR 닫힌루프(인증 컨텍스트 주입 방식 설계 필요). redirect/ssrf 는 POST 미지원(검증 원리상 GET 위주라 우선순위 낮음).
- **임의 레포 자동수정 — 방향 확정(미구현, 2026-08-25)**: 현재 자동수정은 fixes.py 카탈로그가 데모 app.py 에 하드코딩돼 데모 대상에서만 됨. 임의 레포는 create_fix 가 '대상 파일 없음'으로 실패(정직한 안내로 매핑해둠). **채택 방식 = SAST 위치 + LLM 패치**: ①위치는 semgrep(SAST)가 준 file:line(결정론, 환각 방지) ②그 파일 실제 코드를 LLM 이 읽어 패치 생성(임의 레포 일반화). 원칙(검증·위치=결정론, LLM=수정생성만)과 일치. 필요조건: semgrep 설치, fixgen 을 Gemini 로(현재 Anthropic 전용 — 이미 있는 GEMINI 키 재사용 권장), create_fix(repo,kind,file_rel) 의 file_rel 을 SAST finding 에서 배선. 프레임워크별 카탈로그 확장·DAST→소스 자동매핑은 각각 브리틀/불가라 기각.
- UI 더 다듬기(결과카드·로딩·빈상태), Semgrep/Nuclei 실설치 데모(사용자), OAuth 레포연결(구조만),
  알림 채널 확장, 또는 문서화 전환.
- 지금까지 "순수 코드로 리스크 없이 배포 근접"은 거의 소진. 남은 큰 건 외부 서비스 실연동(사용자 계정·키 필요).
