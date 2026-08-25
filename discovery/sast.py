"""
① SAST 입구 — Semgrep(정적 분석) 결과를 후보로 받는 어댑터. Nuclei 때와 같은 패턴.

- Semgrep 있으면 실제 실행(`semgrep --config auto --json`), 없으면 내장 시크릿 스캔으로 폴백.
- 결과는 '정적 탐지(detection)'다 — 실행 없이 코드만 본 것. '검증(verification)'이 아니다.
  진짜인지는 돌아가는 앱에 찔러봐야(DAST) 확정된다 → 우리 파이프라인의 나머지 절반.

Semgrep JSON 형태(핵심):
  {"results":[{"check_id","path","start":{"line"},"extra":{"message","severity","metadata"}}]}
"""
import os
import json
import shutil
import subprocess

import discovery.scan_source as scan_source
import github_pr

SEV_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def semgrep_available():
    return shutil.which("semgrep") is not None


def parse_semgrep(stdout, repo_dir):
    """Semgrep --json 출력 → 정규화된 정적 핀딩 목록. (파서만 분리 — 테스트 가능)"""
    data = json.loads(stdout or "{}")
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        vc = meta.get("vulnerability_class") or [meta.get("category", "static")]
        kind = vc[0] if isinstance(vc, list) and vc else "static"
        try:
            rel = os.path.relpath(r.get("path", ""), repo_dir)
        except ValueError:
            rel = r.get("path", "")
        out.append({
            "file": rel,
            "line": r.get("start", {}).get("line"),
            "rule": r.get("check_id", ""),
            "message": extra.get("message", ""),
            "severity": SEV_MAP.get(extra.get("severity", "INFO"), "low"),
            "kind": kind,
        })
    return out


def run_semgrep(repo_dir, timeout=300):
    r = subprocess.run(["semgrep", "--config", "auto", "--json", "--quiet", repo_dir],
                       capture_output=True, text=True, timeout=timeout)
    return parse_semgrep(r.stdout, repo_dir)


def scan(source):
    """(findings, source_label). source = 레포 URL 또는 로컬 경로."""
    repo = source if os.path.isdir(source) else github_pr.connect_repo(source)
    if semgrep_available():
        try:
            return run_semgrep(repo), "semgrep"
        except Exception as e:
            return _builtin(repo), "builtin(semgrep 실패: %s)" % type(e).__name__
    return _builtin(repo), "builtin(semgrep 미설치)"


def _builtin(repo):
    """폴백: 내장 시크릿 스캔(우리가 할 수 있는 최소 정적 탐지)."""
    return [{"file": rel, "line": ln, "rule": "builtin.secret",
             "message": "하드코딩 시크릿: " + kind, "severity": "high", "kind": "secret"}
            for rel, ln, kind, snip in scan_source.scan_dir(repo)]


if __name__ == "__main__":
    import sys
    f, src = scan(sys.argv[1] if len(sys.argv) > 1 else ".")
    print("출처:", src, "| 정적 탐지:", len(f))
    for x in f[:20]:
        print("  %s:%s [%s] %s" % (x["file"], x["line"], x["kind"], x["message"][:70]))
