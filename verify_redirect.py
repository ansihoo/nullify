"""
오픈 리다이렉트(Open Redirect, A01) 검증기 — 결정론, LLM 없음.

원리: next 파라미터에 외부 도메인을 주면, 서버가 그 외부로 302 시켜주는가?
  - Location 헤더가 우리가 준 외부 도메인을 가리키면 → CONFIRMED
  - 홈('/')이나 같은 사이트로 가면                → FALSE_POSITIVE
리다이렉트를 '따라가지 않고' Location 헤더만 본다.

GET/POST 둘 다 지원 — method 인자로 선택. 판정 로직은 요청 방식과 무관하게 동일.
※ _NoRedirect opener 는 GET/POST 양쪽에서 그대로 유지 — SSRF 와 오픈리다이렉트를
   가르는 회귀 가드의 핵심(3xx 자동추적하면 SSRF 로 오판) 이라 절대 안 건드림.
"""
import urllib.request
import urllib.parse
import urllib.error

EVIL = "//evil.example.com/x"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None   # 자동 추적 끔


_OPENER = urllib.request.build_opener(_NoRedirect)


def verify(base_url, param="next", method="GET"):
    if method.upper() == "POST":
        data = urllib.parse.urlencode({param: EVIL}).encode("utf-8")
        req = urllib.request.Request(
            base_url, data=data, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
    else:
        url = base_url + "?" + urllib.parse.urlencode({param: EVIL})
        req = urllib.request.Request(url, method="GET")
    try:
        r = _OPENER.open(req, timeout=5)
        status, loc = r.status, r.headers.get("Location", "")
    except urllib.error.HTTPError as e:                 # 302 는 여기로 온다
        status, loc = e.code, e.headers.get("Location", "")
    ev = {"method": method, "payload": EVIL, "status": status, "location": loc}
    if "evil.example.com" in loc:
        return "CONFIRMED", "외부 도메인으로 리다이렉트됨 → 오픈 리다이렉트", ev
    return "FALSE_POSITIVE", "외부 도메인 리다이렉트가 차단됨", ev


if __name__ == "__main__":
    from vuln_app import serve_in_thread
    srv = serve_in_thread(8022)
    print("/go", verify("http://127.0.0.1:8022/go"))
    srv.shutdown()