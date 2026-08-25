"""
보안 헤더 누락(Security Misconfiguration, A05) 검증기 — 수동(passive) 결정론.

능동 공격이 아니라 '응답 헤더를 읽어보는' 수동 점검이다.
꼭 있어야 할 보안 헤더가 빠져 있으면 알린다. (오라클 = 헤더 존재 여부, 100% 결정론)
※ 이건 '지금 터진다'기보다 '설정 미흡' 성격이라 심각도는 낮게 다룬다.
"""
import urllib.request
import urllib.error

WANT = ["X-Frame-Options", "Content-Security-Policy"]


def _headers(url):
    try:
        r = urllib.request.urlopen(url, timeout=5)
        return r.headers
    except urllib.error.HTTPError as e:
        return e.headers


def verify(base_url):
    h = _headers(base_url)
    missing = [name for name in WANT if h.get(name) is None]
    ev = {"missing": ", ".join(missing) or "(없음)"}
    if missing:
        return "CONFIRMED", "필수 보안 헤더 누락: " + ", ".join(missing), ev
    return "FALSE_POSITIVE", "필수 보안 헤더가 모두 존재", ev


if __name__ == "__main__":
    from vuln_app import serve_in_thread
    srv = serve_in_thread(8024)
    print("/app", verify("http://127.0.0.1:8024/app"))
    srv.shutdown()
