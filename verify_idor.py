"""
IDOR / 접근제어 검증기 — 여기가 'UNKNOWN(질문하면 확정)' 트랙의 핵심.

왜 자동 확정이 안 되나:
  '남의 주문을 열람할 수 있다'는 기계로 관찰된다(결정론).
  하지만 그게 '문제'인지는 그 데이터가 원래 비공개여야 하는지에 달렸고,
  그 의도는 앱마다 다르다 → 우리는 모른다 → 개발자에게 물어야 한다.

그래서 이 검증기는 'CONFIRMED/FALSE_POSITIVE'가 아니라 UNKNOWN 을 낸다:
  - 교차 계정 열람이 '되면'  → UNKNOWN (+ 개발자에게 던질 질문)
  - '막히면'(403)          → FALSE_POSITIVE
개발자의 답(resolve)이 UNKNOWN 을 CONFIRMED 또는 FALSE_POSITIVE 로 바꾼다.
"""
import urllib.request
import urllib.parse
import urllib.error


def read_order(base, order_id, token):
    url = base + "/order?" + urllib.parse.urlencode({"id": order_id, "token": token})
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def cross_account_test(base, victim_order="1001", victim_owner="alice",
                       attacker_token="sess_bob"):
    """공격자(bob)가 남(alice)의 주문을 열어본다. (열람 성공?, 근거) 반환.
    데모 토이 앱(/order)의 알려진 계정 체계에 특화된 '강한' 증거."""
    _, resp = read_order(base, victim_order, attacker_token)
    leaked = ("owner=%s" % victim_owner) in resp and "forbidden" not in resp
    evidence = {
        "요청자": "bob (sess_bob)",
        "대상": "alice 소유 주문 %s" % victim_order,
        "응답": resp,
    }
    return leaked, evidence


# ── 임의 앱용: 인증 컨텍스트 없이 관찰 가능한 IDOR 신호 = '객체 열거' ──────────
# /path?id=N 옆의 id=N±1 을 찔러, 접근제어 없이 '실질적으로 다른 객체'가
# 200 으로 돌아오면 순차 객체참조가 무방비로 노출된 것 = IDOR 의심.
# 단, 그게 '비공개여야 하는지'는 앱 의도라 여전히 UNKNOWN(질문) 으로만 낸다.
_ERR_MARK = ("forbidden", "not found", "404", "403", "error", "unauthorized",
             "denied", "권한", "없음")


def _get(url, timeout=5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read(50_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(50_000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return None, ""


def _looks_like_record(status, body, baseline):
    """200 + 비어있지 않고 + 에러표식 없고 + baseline 과 '실질적으로 다른' 응답인가."""
    if status != 200 or not body.strip():
        return False
    low = body.lower()
    if any(m in low for m in _ERR_MARK):
        return False
    if body.strip() == baseline.strip():        # 같은 내용이면 열거 아님(정적 페이지 등)
        return False
    # 길이가 극단적으로 다르면(예: 에러 스텁 vs 레코드) baseline 과 같은 '종류'로 보기 어려움.
    a, b = len(body), max(len(baseline), 1)
    if not (0.3 <= a / b <= 3.0):
        return False
    return True


def enumerate_test(base, path, param, id_value):
    """(열거 가능?, 근거) 반환. id 를 ±1 옮겨 다른 객체가 무방비로 나오는지 관찰."""
    try:
        n = int(str(id_value).strip())
    except (TypeError, ValueError):
        return False, {"이유": "id 가 정수가 아니라 순차 열거 판정 불가", "param": param}

    def url_for(v):
        return base + path + "?" + urllib.parse.urlencode({param: v})

    s0, base_body = _get(url_for(n))
    if s0 != 200 or not base_body.strip():
        return False, {"이유": "기준(id=%d) 응답이 정상 레코드가 아님(status=%s)" % (n, s0)}

    hits = []
    for v in (n - 1, n + 1):
        if v < 0:
            continue
        s, body = _get(url_for(v))
        if _looks_like_record(s, body, base_body):
            hits.append({"id": v, "응답": body[:400]})

    if not hits:
        return False, {"이유": "인접 id 에서 접근제어/차이 확인 — 열거로 안 보임"}
    ev = {
        "대상경로": path, "파라미터": param, "기준id": n,
        "열람된_다른객체": hits,
        "설명": "인증/소유권 확인 없이 순차 id 로 다른 객체가 열람됨(무방비 직접참조).",
    }
    return True, ev


if __name__ == "__main__":
    from vuln_app import serve_in_thread
    srv = serve_in_thread(8013)
    leaked, ev = cross_account_test("http://127.0.0.1:8013")
    print("교차 계정 열람:", "성공(UNKNOWN)" if leaked else "차단(FALSE_POSITIVE)")
    print("근거:", ev["응답"])
    srv.shutdown()
