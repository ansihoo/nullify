"""
닫힌 루프 = Nullify 의 결정타.
  BEFORE : 취약 코드에 공격 → secret 탈취 성공 + 검증 CONFIRMED
  PATCH  : 취약 코드를 안전 코드로 교체(= PR 병합 후 재배포), 실제 diff 를 보여줌
  AFTER  : '똑같은 공격'을 다시 → 탈취 실패 + 검증 FALSE_POSITIVE
  RECEIPT: before/after 를 한 장으로 → 이게 사용자에게 주는 '영수증'

전 과정에 LLM 없음: 판정도, 공격도, 재검증도 전부 결정론.
(LLM 은 오직 'diff 를 사람 말로 풀어 설명'하는 데만 나중에 쓴다.)
"""
import inspect
import difflib

import vuln_app
from vuln_app import serve_in_thread, set_user_impl, query_vuln, query_safe
from verify_sqli import verify
from exploit_sqli import find_column_count, union_extract

PAYLOAD = "secret, name FROM users"   # UNION 으로 훔칠 대상


def stolen(body):
    """응답에서 실제로 빠져나온 secret 줄만 골라낸다."""
    return [ln for ln in body.splitlines() if "-secret" in ln]


def make_patch():
    """취약 함수 → 안전 함수의 '진짜 unified diff'. 이게 PR 에 올라갈 내용."""
    before = inspect.getsource(query_vuln).replace("query_vuln", "get_user")
    after  = inspect.getsource(query_safe).replace("query_safe", "get_user")
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile="app.py  (취약)", tofile="app.py  (패치 · PR #7)"))


if __name__ == "__main__":
    srv = serve_in_thread(8011)
    url = "http://127.0.0.1:8011/user"
    print("타깃 /user 배포:", url, "\n")

    # ── BEFORE ─────────────────────────────────────────────
    cols = find_column_count(url)
    _, body_before = union_extract(url, PAYLOAD)
    verdict_before, _, _ = verify(url)
    got_before = stolen(body_before)
    print("BEFORE  판정 = %s" % verdict_before)
    print("        훔친 secret %d건: %s\n" % (len(got_before), ", ".join(got_before)))

    # ── PATCH (배포) ───────────────────────────────────────
    print("PATCH   PR #7 적용 — 취약 코드를 안전 코드로 교체:")
    print("".join("        " + ln for ln in make_patch().splitlines(keepends=True)))
    set_user_impl(query_safe)     # ← 재배포에 해당. 같은 /user, 구현만 안전판으로.
    print()

    # ── AFTER (똑같은 공격 재실행) ─────────────────────────
    _, body_after = union_extract(url, PAYLOAD)   # 동일 payload
    verdict_after, _, _ = verify(url)
    got_after = stolen(body_after)
    print("AFTER   판정 = %s" % verdict_after)
    print("        훔친 secret %d건: %s\n" % (len(got_after), ", ".join(got_after) or "(없음)"))

    # ── RECEIPT ────────────────────────────────────────────
    fixed = (verdict_before == "CONFIRMED" and verdict_after == "FALSE_POSITIVE"
             and len(got_before) > 0 and len(got_after) == 0)
    print("=" * 62)
    print("영수증 (Receipt) — /user · SQL Injection")
    print("  payload : -1' UNION SELECT %s-- " % PAYLOAD)
    print("  before  : 판정 %-14s | secret %d건 탈취" % (verdict_before, len(got_before)))
    print("  after   : 판정 %-14s | secret %d건 탈취" % (verdict_after, len(got_after)))
    print("  결과    : %s" % ("취약점 소멸 확인 — 같은 공격이 이제 실패한다." if fixed
                              else "확인 실패(로직 점검 필요)"))
    print("=" * 62)

    srv.shutdown()
