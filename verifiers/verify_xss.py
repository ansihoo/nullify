"""
결정론적 반사형 XSS 검증기 — SQLi 와 같은 철학, LLM 없음.

원리:
  입력이 응답 HTML 에 '이스케이프 없이 그대로' 반사되면, 공격자가 <script>/이벤트
  핸들러를 심을 수 있다 = XSS. 판정 기준은 딱 하나:
    "우리가 넣은 특수문자(<, >)가 원문 그대로 응답에 나타나는가?"
  - 그대로면      → CONFIRMED (실행 가능)
  - 이스케이프되면 → FALSE_POSITIVE (&lt; 등으로 무력화)
  - 반사 안 되면   → FALSE_POSITIVE (여기선 안 터짐)
고유 마커(random)를 써서 '우연히 페이지에 있던 값'과 헷갈리지 않게 한다.

GET/POST 둘 다 지원 — method 인자로 선택. 판정 로직은 요청 방식과 무관하게 동일.
"""
import secrets
import urllib.request
import urllib.parse
import urllib.error


def fetch(base_url, param, value, method="GET"):
    """base_url 에 payload 를 실어 요청. (상태코드, 본문) 반환.
       GET: ?param=value. POST: form-urlencoded 바디."""
    if method.upper() == "POST":
        data = urllib.parse.urlencode({param: value}).encode("utf-8")
        req = urllib.request.Request(
            base_url, data=data, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
    else:
        url = base_url + "?" + urllib.parse.urlencode({param: value})
        req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def verify(base_url, param="q", method="GET"):
    mark = "xq" + secrets.token_hex(3)               # 이번 검사에만 쓰는 고유 표식
    payload = mark + "<img src=x onerror=alert(1)>" + mark   # 실행형 프로브
    _, body = fetch(base_url, param, payload, method)
    evidence = {"method": method, "payload": payload}

    if payload in body:                              # 특수문자까지 원문 그대로 반사
        i = body.find(mark)
        evidence["reflected_raw"] = body[i:i + len(payload)]
        return ("CONFIRMED",
                "입력이 이스케이프 없이 HTML 에 그대로 반사됨 → 브라우저가 태그를 실행",
                evidence)

    if mark in body:                                 # 반사는 되나 특수문자가 죽음
        i = body.find(mark)
        evidence["reflected_escaped"] = body[i:i + 80]
        return ("FALSE_POSITIVE",
                "반사되지만 특수문자가 이스케이프됨(&lt; 등) → 실행 불가", evidence)

    return "FALSE_POSITIVE", "입력이 응답에 반사되지 않음", evidence


if __name__ == "__main__":
    from vuln_app import serve_in_thread
    srv = serve_in_thread(8012)
    for path in ("/search", "/search_safe"):
        v, why, ev = verify("http://127.0.0.1:8012" + path)
        print("%-14s %s | %s" % (path, v, why))
    srv.shutdown()