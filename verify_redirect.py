"""
오픈 리다이렉트(Open Redirect, A01) 검증기 — 결정론, LLM 없음.

원리: next 파라미터에 외부 도메인을 주면, 서버가 그 외부로 302 시켜주는가?
  - Location 헤더가 우리가 준 외부 도메인을 가리키면 → CONFIRMED
  - 홈('/')이나 같은 사이트로 가면                → FALSE_POSITIVE
리다이렉트를 '따라가지 않고' Location 헤더만 본다.
"""
import urllib.request
import urllib.parse
import urllib.error

EVIL = "//evil.example.com/x"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None   # 자동 추적 끔


_OPENER = urllib.request.build_opener(_NoRedirect)


def verify(base_url, param="next"):
    url = base_url + "?" + urllib.parse.urlencode({param: EVIL})
    try:
        r = _OPENER.open(url, timeout=5)
        status, loc = r.status, r.headers.get("Location", "")
    except urllib.error.HTTPError as e:                 # 302 는 여기로 온다
        status, loc = e.code, e.headers.get("Location", "")
    ev = {"payload": EVIL, "status": status, "location": loc}
    if "evil.example.com" in loc:
        return "CONFIRMED", "외부 도메인으로 리다이렉트됨 → 오픈 리다이렉트", ev
    return "FALSE_POSITIVE", "외부 도메인 리다이렉트가 차단됨", ev


if __name__ == "__main__":
    from vuln_app import serve_in_thread
    srv = serve_in_thread(8022)
    print("/go", verify("http://127.0.0.1:8022/go"))
    srv.shutdown()
