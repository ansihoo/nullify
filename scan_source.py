"""
소스코드 시크릿 스캔 — 클론한 레포에서 하드코딩된 비밀을 찾는다(정적, 결정론).

DAST(찔러보기)와 달리 이건 SAST 성격 — 실행 없이 파일 텍스트를 본다.
정규식 기반이라 환각 없음, 읽기 전용이라 안전, 임의 레포에 그대로 붙는다.
근거는 '파일:라인'으로 낸다.

한계(정직):
  - 시크릿은 잘 잡지만, SQLi/XSS 같은 '데이터 흐름' 취약점은 이 방식으론 못 찾는다.
    그건 Semgrep/CodeQL 같은 진짜 SAST 엔진을 (Nuclei 처럼) 붙여 후보로 받아야 한다.
"""
import os
import re

PATTERNS = [
    ("AWS 액세스 키", re.compile(r"AKIA[0-9A-Z]{12,}")),
    ("개인키(PEM)", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("하드코딩 비밀", re.compile(
        r"""(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"""
        r"""\s*[:=]\s*["'][^"']{6,}["']""")),
    ("토큰 리터럴", re.compile(r"""(?i)(token|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']""")),
]

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
MAX_BYTES = 1_000_000   # 1MB 넘는 파일은 건너뜀(바이너리/대용량)


def scan_dir(root):
    """(파일, 라인번호, 종류, 스니펫) 목록 반환."""
    findings = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    continue
                with open(path, encoding="utf-8") as f:
                    lines = f.readlines()
            except (OSError, UnicodeDecodeError):
                continue   # 바이너리/읽기 불가 → 건너뜀
            rel = os.path.relpath(path, root)
            for i, line in enumerate(lines, 1):
                for kind, rx in PATTERNS:
                    m = rx.search(line)
                    if m:
                        snippet = line.strip()[:120]
                        findings.append((rel, i, kind, snippet))
                        break
    return findings


def scan_github(source):
    """레포를 clone 한 뒤 시크릿 스캔. (findings, clone_path)"""
    import github_pr
    clone = github_pr.connect_repo(source)
    return scan_dir(clone), clone


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    for rel, ln, kind, snip in scan_dir(target):
        print("%s:%d  [%s]  %s" % (rel, ln, kind, snip))
