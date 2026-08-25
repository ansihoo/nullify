"""
결정론적 SQL 인젝션 검증기 — 이 파일이 Nullify 의 '심장'이다.

핵심 원칙: 판정에 LLM 을 쓰지 않는다.
  - LLM 에게 "이거 취약해?" 라고 물으면 환각(없는 걸 있다고, 있는 걸 없다고)이 난다.
  - 대신 '우리가 넣은 논리식이 실제 SQL 에 섞였는지'를 응답 차이로 확인한다.
    → 근거가 재현 가능(같은 요청 = 같은 결과)하므로 심사·현업 질문에 무너지지 않는다.

방법(불리언 기반 차분):
  baseline : id=1                 → 정상 결과
  참  조건 : id=1' AND '1'='1     → 주입되면 WHERE 가 항상 참 → baseline 과 같아짐
  거짓 조건 : id=1' AND '1'='2     → 주입되면 WHERE 가 항상 거짓 → 결과가 사라짐
  '참과 거짓의 결과가 갈리면' 우리가 넣은 논리식이 SQL 로 해석됐다는 뜻 = 취약.

2026-08-25: fetch/verify 에 method="GET"|"POST" 인자 추가.
GET 은 기존과 동일(쿼리스트링). POST 는 같은 payload 를 폼 바디로 보낸다.
판정 로직(불리언 차분)은 요청 방식과 무관하게 동일 — 손 안 댐.
"""
import difflib
import urllib.request
import urllib.parse
import urllib.error


def fetch(base_url, value, param="id", method="GET"):
    """
    (원본)
    def fetch(base_url, value, param="id"):
        url = base_url + "?" + urllib.parse.urlencode({param: value})
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
    """
    # (변경) method="GET"|"POST" 인자 추가. GET 은 기존과 동일(쿼리스트링).
    #        POST 는 같은 payload 를 폼 바디로 보낸다.
    #        (positional 인자 순서는 유지 — exploit_sqli.py 하위호환)
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
    except urllib.error.HTTPError as e:  # 500 등도 본문을 읽어 근거로 쓴다
        return e.code, e.read().decode("utf-8", "replace")


def sim(a, b):
    """두 응답 본문의 유사도(0~1). difflib 은 표준 라이브러리."""
    return difflib.SequenceMatcher(None, a, b).ratio()


def verify(base_url, param="id", T=0.95, method="GET"):
    """
    반환: (verdict, reason, evidence)
      verdict ∈ {CONFIRMED, FALSE_POSITIVE, UNKNOWN}
    method 로 GET/POST 선택. 판정 로직은 요청 방식과 무관하게 동일.

    (원본)
    def verify(base_url, param="id", T=0.95):
        _, baseline   = fetch(base_url, "1", param)
        _, true_resp  = fetch(base_url, "1' AND '1'='1", param)
        _, false_resp = fetch(base_url, "1' AND '1'='2", param)
        evidence = {
            "baseline (id=1)":            baseline,
            "true  (id=1' AND '1'='1)":   true_resp,
            "false (id=1' AND '1'='2)":   false_resp,
        }
    """
    # (변경) method 인자 추가 → fetch 로 그대로 전달. 아래 판정 로직은 원본과 동일.
    _, baseline   = fetch(base_url, "1", param, method)
    _, true_resp  = fetch(base_url, "1' AND '1'='1", param, method)
    _, false_resp = fetch(base_url, "1' AND '1'='2", param, method)

    evidence = {
        "method": method,
        "baseline (%s=1)"          % param: baseline,
        "true  (%s=1' AND '1'='1)" % param: true_resp,
        "false (%s=1' AND '1'='2)" % param: false_resp,
    }

    # (1) 에러 기반 신호: 따옴표를 넣었더니 SQL 오류가 새어나오면 강한 근거.
    if "SQL error" in true_resp or "SQL error" in false_resp:
        return "CONFIRMED", "따옴표 주입 시 SQL 오류가 노출됨(에러 기반 근거)", evidence

    # (2) 불리언 차분: 참/거짓 조건이 결과를 '갈랐는가?'
    if sim(true_resp, false_resp) < T:            # 참 ≠ 거짓 → 논리식이 결과에 영향
        if sim(true_resp, baseline) >= T:         # 참 조건이 원본과 같음 → 교과서적 확진
            return ("CONFIRMED",
                    "참 조건=원본과 동일, 거짓 조건=결과 소멸 → 넣은 논리식이 실제 SQL 에 섞임",
                    evidence)
        return ("UNKNOWN",
                "결과가 갈렸으나 전형적 패턴과 달라 사람 확인 필요", evidence)

    # (3) 참 ≈ 거짓 → 우리가 넣은 논리식이 결과를 못 바꿈 → 입력이 SQL 로 안 쓰임.
    return ("FALSE_POSITIVE",
            "참/거짓 조건이 결과를 바꾸지 못함 → 입력이 SQL 로 해석되지 않음", evidence)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8009/user"
    method = sys.argv[2] if len(sys.argv) > 2 else "GET"
    v, why, ev = verify(target, method=method)
    print("판정 [%s]:" % method, v, "|", why)