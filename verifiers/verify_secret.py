"""
노출된 시크릿(Cryptographic/Sensitive Data Exposure, A02) 검증기 — 수동 결정론.

프론트로 서빙되는 파일(예: config.js)에 API 키/시크릿이 박혀 있는지 정규식으로 찾는다.
여기선 AWS 액세스 키 형태(AKIA...)를 예로 쓴다. (오라클 = 패턴 매칭, 결정론)
※ URL 만 있어도 되는 '모드 B(프론트)' 대표 점검.
"""
import re
import urllib.request
import urllib.error

# AWS 액세스 키 ID 패턴(단순화). 실전에선 여러 시크릿 패턴 + 엔트로피를 함께 본다.
KEY_RE = re.compile(r"AKIA[0-9A-Z]{12,}")


def _body(url):
    try:
        return urllib.request.urlopen(url, timeout=5).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace")


def verify(base_url):
    body = _body(base_url)
    m = KEY_RE.search(body)
    if m:
        return "CONFIRMED", "프론트 코드에 시크릿(API 키)이 노출됨", {"matched": m.group()}
    return "FALSE_POSITIVE", "노출된 시크릿 패턴 없음", {}


if __name__ == "__main__":
    from vuln_app import serve_in_thread
    srv = serve_in_thread(8025)
    print("/config.js", verify("http://127.0.0.1:8025/config.js"))
    srv.shutdown()
