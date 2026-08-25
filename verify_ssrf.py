"""
SSRF(Server-Side Request Forgery, A10) 검증기 — 결정론, LLM 없음.

원리: 서버에게 '내부 전용' URL 을 대신 가져오라고 시킨다.
  공격자는 원래 /internal 에 직접 접근 못 하지만, 서버는 접근할 수 있다.
  응답에 내부 전용 표식이 돌아오면 → 서버가 공격자 지정 URL 을 대신 가져온 것 = SSRF.
  - 표식 나옴 → CONFIRMED
  - 'blocked' → FALSE_POSITIVE

2026-08-25: fetch/verify 에 method="GET"|"POST" 인자 추가.
GET 은 기존과 동일(쿼리스트링). POST 는 같은 payload 를 폼 바디로 보낸다.
★ _NoRedirect opener(리다이렉트 미추적)는 POST 에서도 그대로 유지 —
  이게 오픈리다이렉트를 SSRF 로 오판하지 않게 막는 회귀 가드의 핵심이라 안 건드림.
"""
import urllib.request
import urllib.parse
import urllib.error

MARKER = "INTERNAL_ONLY_SECRET"


# 리다이렉트를 따라가지 않는 opener.
# SSRF 는 '서버가' 내부 URL 을 대신 가져와 그 내용을 응답 본문에 실어줄 때만 성립한다.
# 만약 여기서 3xx 를 자동 추적하면, 단순 오픈 리다이렉트(/go?next=<내부URL>)도
# 검증기의 클라이언트가 대신 따라가 내부 표식을 보게 되어 SSRF 로 오판한다.
# → 오픈 리다이렉트와 SSRF 를 가르는 핵심이 '리다이렉트 미추적'이다.
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch(base_url, param, value, method="GET"):
    """
    (원본)
    def fetch(base_url, param, value):
        url = base_url + "?" + urllib.parse.urlencode({param: value})
        try:
            with _OPENER.open(url, timeout=5) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
    """
    # (변경) method="GET"|"POST" 인자 추가. GET 은 기존과 동일(쿼리스트링).
    #        POST 는 같은 payload 를 폼 바디로 보낸다. opener(_OPENER)는 그대로 —
    #        리다이렉트 미추적 동작을 GET/POST 양쪽에서 동일하게 유지(회귀 가드).
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
    """
    (원본)
    def verify(base_url, internal_url, param="url"):
        _, body = fetch(base_url, param, internal_url)
        ev = {"payload": internal_url, "response": body}
    """
    # (변경) method 인자 추가 → fetch 로 그대로 전달. 아래 판정 로직은 원본과 동일.
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