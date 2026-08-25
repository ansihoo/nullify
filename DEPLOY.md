# Nullify — 배포 방향성 (정직한 로드맵)

목표: "지금 당장 배포 가능한" 수준. 아직 아니다. 아래가 데모 → 배포의 실제 간극이다.

## 지금 되는 것 (배포 근접)
- **임의 엔드포인트/파라미터 타격**: 검증기가 param 을 인자로 받아 아무 앱에 붙는다.
- **권한 게이트(`authorize.py`)**: 로컬/사설망 자동 허용, 공개 대상은 거부(소유권 증명 요구).
- **결정론 검증 10종**(SQLi·XSS·LFI·CmdI·OpenRedirect·SSRF·Secret·Headers·Component·IDOR).
- **엔진↔과녁 분리**: 엔진은 대상을 import 하지 않고 HTTP 로만 스캔(진짜 외부 스캐너).
  `NULLIFY_TARGET=http://내대상 python web.py` 로 외부 대상 지정.
- **레포 clone 연결**(`github_pr.connect_repo`): repo URL/경로를 실제 clone → 수정 브랜치 생성.
- **수정 생성 3단**(`fixgen.py`): 카탈로그(결정론) → LLM(`ANTHROPIC_API_KEY` 설정 시) → 전문가 검토.
- **스캐너 어댑터**(`ingest.py`): Nuclei JSONL 호환.
- **실 Nuclei 연동**(`scanner.py`): `NULLIFY_USE_NUCLEI=1` + nuclei 설치 시 실제 실행,
  아니면 샘플로 폴백. `/healthz` 와 스캔 결과에 출처(nuclei/sample) 표시.
- **SAST 연동**(`sast.py`, `/api/scan_source`): Semgrep 있으면 소스 정적 분석, 없으면 내장 시크릿 스캔 폴백.
  결과는 '정적 탐지(미검증)'로 분리 표시 — 검증(재현)은 여전히 DAST 몫.
- **완전체 결합**(`combine.py`, `/api/scan_combined`): DAST+SAST 를 kind 로 상관시켜 증거 등급 부여 —
  정적+동적(가장 강함) / 동적확인 / 정적만(미검증). 소스와 실행 앱 양쪽 신호를 한 리포트로.
- **상태 저장·이력**(`store.py`, SQLite): 스캔·핀딩 저장, 이력 조회/복원.
- **재검증 추적**: 이전 스캔 대비 고쳐짐/새로생김/그대로 비교(`/api/rescan`) — 리그레션 감지.
- **엔진 인증**(`NULLIFY_API_TOKEN`): 설정 시 `/api/*` 에 토큰 요구(X-API-Token). 미설정=개발 모드(경고 로그).
- **UI 로그인**: 토큰 켜지면 브라우저가 토큰 입력·localStorage 저장·모든 요청에 헤더 첨부. 401 시 재입력.
- **멀티테넌시**(`store.py` users): 계정별 토큰(SHA-256 해시 저장), 스캔·이력·알림을 user_id 로 격리.
  계정 발급 CLI: `python store.py adduser <이름>` → 토큰 1회 출력. 모드: 개발(open)/단일(single)/멀티(multi).
- **요청 제한**(`NULLIFY_RATE_MAX`, 기본 30/분): 스캔 남용/DoS 방지.
- **알림**(`notify.py`): 리그레션 감지 시 로컬 로그 저장, `NULLIFY_WEBHOOK` 설정 시 Slack 호환 전송.
- **패키징**: `docker build -t nullify . && docker run -p 8000:8000 nullify`
- **서버 견고화**: 동시성(ThreadingHTTPServer), `/healthz`, 에러 격리(500 JSON), 구조화 로그,
  스캔 직렬화(공유 타깃 경합 방지), 환경설정(`NULLIFY_HOST`/`NULLIFY_PORT`/`NULLIFY_TARGET`).

## CI 파이프라인 (구조 완성 — 실 연결은 레포 소유자)
- **보안 게이트**(`nullify_ci.py`): CI 에서 엔진을 호출해 대상 스캔 → 진짜 취약점 있으면 exit 1(빌드 실패).
  `NULLIFY_TARGET=<url> NULLIFY_FAIL_ON=critical python nullify_ci.py`
- **GitHub Actions**(`.github/workflows/nullify.yml`): PR 시 스테이징 스캔 → 머지 차단. 시크릿(엔진주소·토큰)만 연결하면 동작.
- **리그레션 추적**: `NULLIFY_MODE=rescan` 으로 이전 배포 대비 '새로 생긴' 취약점 감지 + GitHub 주석/요약.
- 한계: 실 배포 앱엔 `/control` 이 없어 '수정 후 재검증(영수증)'은 데모 전용. CI 값 = 탐지 게이트 + 배포 간 리그레션.

## 배포 전 반드시 (아직 안 됨)
1. **데모 과녁 분리**: `web.py` 가 취약 앱(`vuln_app`)을 함께 띄운다 → 운영 빌드에서 제거.
2. **소유권 증명**: 공개 대상 스캔은 DNS TXT 챌린지 등으로 '내 자산'임을 검증해야 함.
   지금은 사설망만 통과시키는 게 안전장치.
3. **닫힌 루프 재설계**: 지금은 우리가 과녁 코드를 교체해 재검증. 실제로는
   사용자 레포에 PR → CI 재배포 → 우리가 재스캔, 파이프라인이 필요.
4. **인프라**: 단일스레드 stdlib 서버 → ASGI + 작업 큐 + DB + 사용자 계정.
5. **탈취 범위 제한**: 실데이터 대신 무해한 카나리(예: sqlite_version)만 뽑도록 강제.

## 실행
```bash
python web.py                 # http://127.0.0.1:8000
python selftest.py            # 검증기 전체 자가진단
```
