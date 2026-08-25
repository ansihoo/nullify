"""
SSRF(Server-Side Request Forgery, A10) 검증기 — 결정론, LLM 없음.

원리: 서버에게 '내부 전용' URL 을 대신 가져오라고 시킨다.
  공격자는 원래 /internal 에 직접 접근 못 하지만, 서버는 접근할 수 있다.
  응답에 내부 전용 표식이 돌아오면 → 서버가 공격자 지정 URL 을 대신 가져온 것 = SSRF.
  - 표식 나옴 → CONFIRMED
  - 'blocked' → FALSE_POSITIVE

GET/POST 둘 다 지원 — method 인자로 선택. 판정 로직은 요청 방식과 무관하게 동일.
※ _NoRedirect opener 는 GET/POST 양쪽에서 그대로 유지 — 3xx 자동추적하면
   단순 오픈 리다이렉트(/go?next=<내부URL>)를 SSRF 로 오판하는 회귀 가드의 핵심.
"""
import urllib.request
import urllib.parse
import urllib.error

MARKER = "INTERNAL_ONLY_SECRET"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch(base_url, param, value, method="GET"):
    """base_url 에 payload 를 실어 요청. (상태코드, 본문) 반환.
       GET: ?param=value. POST: form-urlencoded 바디. opener 는 리다이렉트 미추적."""
    if method.upper() == "POST":
        data = urllib.parse.urlencode({param: value}).encode("utf-8")
        req = urllib.request.Request(
            base_url, data=data, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
    else:
        url = base_url + "?" + urllib.parse.urlencode({param: value})
        req = urllib.request.Request(url, method="GET")
    try:
        with _OPENER.open(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def verify(base_url, internal_url, param="url", method="GET"):
    _, body = fetch(base_url, param, internal_url, method)
    ev = {"method": method, "payload": internal_url, "response": body}
    if MARKER in body:
        return "CONFIRMED", "서버가 공격자 지정 내부 URL 을 대신 가져옴 → SSRF", ev
    return "FALSE_POSITIVE", "내부 대상 접근이 차단됨", ev


if __name__ == "__main__":
    from vuln_app import serve_in_thread
    srv = serve_in_thread(8023)
    b = "http://127.0.0.1:8023"
    print("/fetch", verify(b + "/fetch", b + "/internal")[0])
    srv.shutdown()