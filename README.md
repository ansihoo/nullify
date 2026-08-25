# Nullify

**보안 스캐너가 쏟아내는 오탐 검수 노동을, 실제로 찔러 보는 결정론적 검증으로 없앤다.**

스캐너(Nuclei/Semgrep) 결과를 입구로 받아 → **LLM 없이 실제로 찔러 보고** → 진짜 터지는 것만 골라 →
고치고 → **같은 공격을 재실행해 "죽었음"을 증명(영수증)** → 이력·추세를 추적한다.
차별점: 검증에는 LLM을 쓰지 않는다(환각 방지). LLM은 *수정 생성*에만.

2026 UNITHON 출품작 · Python 표준 라이브러리만 사용.

## 빠른 시작

```bash
# Windows 콘솔은 cp949라 한글이 깨져 보여도 실제 출력은 UTF-8 정상
PYTHONUTF8=1 PYTHONIOENCODING=utf-8 python web.py       # 엔진 :8000 + 과녁앱 :8009 자동 spawn
PYTHONUTF8=1 PYTHONIOENCODING=utf-8 python selftest.py  # 자가진단 — 전부 PASS 여야 정상
```

브라우저에서 http://127.0.0.1:8000 접속.

## 절대 지킬 원칙

- **검증 = 결정론.** 참/거짓 응답 차분, 실제 exploit 재현으로 판정. 검증에 LLM 금지.
- **LLM은 수정 생성에만** (`fixgen.py`, `ANTHROPIC_API_KEY` 있을 때만).
- **주장엔 근거를** — 취약점 주장은 `파일:라인` + 실제 트리거 입력으로. 추측은 추측이라 라벨.
- **권한 게이트** — 공개 URL 거부. 로컬·사설망·소유 증명된 대상만.

## 더 알아보기

전체 맥락(파일 지도·환경변수·설계 원칙·실전 검증 사례·현재 상태)은 **[HANDOFF.md](HANDOFF.md)** 에 정리돼 있다.
AI 어시스턴트로 이어서 개발한다면 그 파일부터 읽히면 된다.

## 주요 구성

| 파일 | 역할 |
|------|------|
| `web.py` | 엔진·오케스트레이터. 다중페이지 UI + 모든 API |
| `verify_*.py` | 검증기 10종(sqli/xss/idor/traversal/cmdi/redirect/ssrf/headers/secret/component). 결정론 |
| `discover.py` | 후보 자동발견 — 외부 스캐너 없이 크롤+탐침으로 임의 앱 대응 |
| `exploit_sqli.py` | UNION 컬럼수 탐지 + 데이터 탈취 |
| `fixes.py` · `fixgen.py` | 수정 카탈로그 / LLM 수정 생성 |
| `github_pr.py` | 실제 git 브랜치·커밋·clone |
| `store.py` · `notify.py` | SQLite(스캔·이력·계정) / 리그레션 알림 |
| `vuln_app.py` | 일부러 취약한 데모 과녁(별도 프로세스, 실제 제품 아님) |
| `selftest.py` | 자가진단 — 전부 PASS 확인용 |
