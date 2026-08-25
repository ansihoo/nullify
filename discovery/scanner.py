"""
① 스캐너 실행 — 실제 Nuclei 를 돌려 후보를 만든다(있으면). 없으면 샘플로 폴백.

Nuclei = 오픈소스 취약점 스캐너. 우리는 이걸 '입력'으로만 쓴다(다시 만들지 않음).
  실제 실행:  nuclei -u <target> -jsonl -silent -o out.jsonl
  그 JSONL 을 ingest.py 어댑터로 우리 후보 형식으로 번역한다.

정책:
  - NULLIFY_USE_NUCLEI=1 이고 nuclei 가 PATH 에 있으면 → 실제 실행.
  - 아니면 → 샘플 리포트(scanner_report.jsonl)로 폴백.
  실 실행은 nuclei 설치 + (최초 실행 시) 템플릿 다운로드 네트워크가 필요하다.
"""
import os
import shutil
import tempfile
import subprocess

from discovery.ingest import load_candidates

# 샘플 리포트는 프로젝트 루트에 있음. 이 파일은 discovery/ 안이라 상위로 한 단계 올라감.
SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "scanner_report.jsonl")


def nuclei_available():
    return shutil.which("nuclei") is not None


def run_nuclei(target, timeout=180):
    """nuclei 실행 → JSONL 결과 파일 경로. (설치 + 네트워크 필요)"""
    out = os.path.join(tempfile.mkdtemp(prefix="nuclei_"), "out.jsonl")
    subprocess.run(["nuclei", "-u", target, "-jsonl", "-silent", "-o", out],
                   capture_output=True, text=True, timeout=timeout)
    return out


def candidates_for(target, prefer_discover=False):
    """(후보 리스트, 출처 라벨) 반환.

    우선순위:
      1) NULLIFY_USE_NUCLEI=1 이고 nuclei 설치됨 → 실제 Nuclei 실행.
      2) prefer_discover(요청 플래그) 또는 NULLIFY_DISCOVER=1
                            → 내장 크롤러로 대상 앱을 직접 훑어 후보 발견(임의 앱 대응).
      3) 그 외              → 샘플 리포트(scanner_report.jsonl)로 폴백(데모).
    """
    want = os.environ.get("NULLIFY_USE_NUCLEI") == "1"
    if want and nuclei_available():
        try:
            cands = load_candidates(run_nuclei(target))
            if cands:
                return cands, "nuclei"
            return [], "nuclei(결과 없음)"
        except Exception as e:
            return load_candidates(SAMPLE), "sample(nuclei 실패: %s)" % type(e).__name__

    # ② 외부 스캐너 없이도 임의 앱에서 후보를 찾는다(내장 discovery).
    if prefer_discover or os.environ.get("NULLIFY_DISCOVER") == "1":
        try:
            from discovery import discover
            cands = discover.discover(target)
            if cands:
                return cands, "discover(내장 크롤러)"
            return [], "discover(발견 0건)"
        except Exception as e:
            return load_candidates(SAMPLE), "sample(discover 실패: %s)" % type(e).__name__

    reason = "nuclei 미설치" if want else "샘플 모드"
    return load_candidates(SAMPLE), "sample(%s)" % reason


if __name__ == "__main__":
    print("nuclei 설치:", nuclei_available())
    cands, src = candidates_for("http://127.0.0.1:8009")
    print("출처:", src, "| 후보:", len(cands))