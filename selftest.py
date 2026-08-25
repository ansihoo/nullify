"""
자가진단 — '이게 진짜 되는가?'를 당신이 직접 확인하는 스크립트.

내 말을 믿지 말고 이걸 돌려보세요:
    python selftest.py
각 검증기를 실제 과녁에 붙여 '기대한 판정이 나오는지'를 PASS/FAIL 로 보여준다.
하나라도 FAIL 이면 뭔가 잘못된 것 — 전부 PASS 여야 데모가 성립한다.

GET 뿐 아니라 POST 케이스도 포함 — 능동 검증기 6종이 두 방식 모두에서 동작하는지 검증.
"""
from vuln_app import serve_in_thread
from verify_sqli import verify as v_sqli
from verify_xss import verify as v_xss
from verify_traversal import verify as v_trav
from verify_idor import cross_account_test, enumerate_test
from verify_cmdi import verify as v_cmd
from verify_redirect import verify as v_red
from verify_ssrf import verify as v_ssrf
from verify_headers import verify as v_hdr
from verify_secret import verify as v_sec
from verify_component import verify as v_cmp
from exploit_sqli import union_extract

srv = serve_in_thread(8020)
B = "http://127.0.0.1:8020"

cases = [
    # SQLi — GET/POST 양쪽에서 취약/안전 판별
    ("SQLi   취약 /user",              v_sqli(B + "/user")[0],                        "CONFIRMED"),
    ("SQLi   취약 /user POST",         v_sqli(B + "/user", method="POST")[0],         "CONFIRMED"),
    ("SQLi   안전 /user_safe POST",    v_sqli(B + "/user_safe", method="POST")[0],    "FALSE_POSITIVE"),
    ("SQLi   안전 /user_safe",         v_sqli(B + "/user_safe")[0],                   "FALSE_POSITIVE"),
    # XSS — GET/POST 양쪽에서 취약/안전 판별
    ("XSS    취약 /search",            v_xss(B + "/search")[0],                       "CONFIRMED"),
    ("XSS    취약 /search POST",       v_xss(B + "/search", method="POST")[0],        "CONFIRMED"),
    ("XSS    안전 /search_safe POST",  v_xss(B + "/search_safe", method="POST")[0],   "FALSE_POSITIVE"),
    ("XSS    안전 /search_safe",       v_xss(B + "/search_safe")[0],                  "FALSE_POSITIVE"),
    # 나머지 능동 검증기 — GET/POST 양쪽
    ("LFI    취약 /download",          v_trav(B + "/download")[0],                    "CONFIRMED"),
    ("LFI    취약 /download POST",     v_trav(B + "/download", method="POST")[0],     "CONFIRMED"),
    ("CmdI   취약 /ping",              v_cmd(B + "/ping")[0],                         "CONFIRMED"),
    ("CmdI   취약 /ping POST",         v_cmd(B + "/ping", method="POST")[0],          "CONFIRMED"),
    ("Redir  취약 /go",                v_red(B + "/go")[0],                           "CONFIRMED"),
    ("Redir  취약 /go POST",           v_red(B + "/go", method="POST")[0],            "CONFIRMED"),
    ("SSRF   취약 /fetch",             v_ssrf(B + "/fetch", B + "/internal")[0],      "CONFIRMED"),
    ("SSRF   취약 /fetch POST",        v_ssrf(B + "/fetch", B + "/internal", method="POST")[0], "CONFIRMED"),
    # 수동/특수 (method 개념 없음)
    ("Header 취약 /app",               v_hdr(B + "/app")[0],                          "CONFIRMED"),
    ("Secret 취약 /config.js",         v_sec(B + "/config.js")[0],                    "CONFIRMED"),
    ("Comp   취약 /assets",            v_cmp(B + "/assets")[0],                       "CONFIRMED"),
    ("IDOR   교차열람 /order",         "UNKNOWN" if cross_account_test(B)[0] else "FALSE_POSITIVE", "UNKNOWN"),
]

print("=" * 56)
all_ok = True
for name, got, expect in cases:
    ok = (got == expect)
    all_ok = all_ok and ok
    print(("[PASS]" if ok else "[FAIL]"), name.ljust(26), got, "(기대:", expect + ")")

# 공격 재현도 실제로 되는지 확인 (secret 3건 탈취)
_, body = union_extract(B + "/user", "secret, name FROM users")
stolen = [ln.split(",")[0] for ln in body.splitlines() if "-secret" in ln]
ok = (len(stolen) == 3)
all_ok = all_ok and ok
print(("[PASS]" if ok else "[FAIL]"), "SQLi  공격재현(탈취)".ljust(26), "%d건" % len(stolen), "(기대: 3건)")

# 후보 자동발견(discovery): 외부 스캐너 없이 임의 앱에서 엔드포인트를 찾는지.
# 토이 앱은 인덱스가 없어 크롤로는 안 걸리므로 '탐침'이 핵심 경로를 찾아야 한다.
import discover
found_kinds = {c["kind"] for c in discover.discover(B)}
need = {"sqli", "xss", "traversal", "cmdi", "ssrf", "redirect", "secret", "component", "headers"}
missing = need - found_kinds
ok = not missing
all_ok = all_ok and ok
print(("[PASS]" if ok else "[FAIL]"), "Discover 후보발견".ljust(26),
      "%d종" % len(found_kinds), "(기대: %d종 포함, 누락:%s)" % (len(need), sorted(missing) or "없음"))

# SSRF vs 오픈리다이렉트 구분(검증기가 리다이렉트를 따라가면 오판) — 고정 회귀 가드.
red_go = v_red(B + "/go")[0]                       # /go 는 redirect 여야
ssrf_go = v_ssrf(B + "/go", B + "/internal")[0]    # /go 를 ssrf 로 찌르면 오탐이면 안 됨
ok = (red_go == "CONFIRMED" and ssrf_go == "FALSE_POSITIVE")
all_ok = all_ok and ok
print(("[PASS]" if ok else "[FAIL]"), "SSRF≠Redirect 구분".ljust(26),
      "go=redir:%s ssrf:%s" % (red_go, ssrf_go), "(기대: CONFIRMED / FALSE_POSITIVE)")

# 임의경로 IDOR 일반화(객체 열거) — 인증 없이 순차 id 로 다른 객체가 열람되는지.
# 토이 앱 /user 는 id 로 서로 다른 사용자 레코드를 접근제어 없이 돌려줌 → 열거 가능.
leaked_enum, _ = enumerate_test(B, "/user", "id", "1")
# 존재하지 않는 경로는 열거로 안 잡혀야(오탐 방지).
leaked_none, _ = enumerate_test(B, "/nope_xyz", "id", "1")
ok = (leaked_enum and not leaked_none)
all_ok = all_ok and ok
print(("[PASS]" if ok else "[FAIL]"), "IDOR 열거 일반화".ljust(26),
      "user:%s nope:%s" % (leaked_enum, leaked_none), "(기대: True / False)")

# SQLi 공격재현 POST — 팀원이 추가한 회귀 가드. exploit_sqli 도 POST 지원한다.
_, body_post = union_extract(B + "/user", "secret, name FROM users", method="POST")
stolen_post = [ln.split(",")[0] for ln in body_post.splitlines() if "-secret" in ln]
ok = (len(stolen_post) == 3)
all_ok = all_ok and ok
print(("[PASS]" if ok else "[FAIL]"), "SQLi 공격재현 POST".ljust(26), "%d건" % len(stolen_post), "(기대: 3건)")

# Discover 폼 POST 인식 — 폼의 method 속성을 읽어 후보에 POST 를 담는지.
# 여기선 discover 결과에 POST 후보가 하나라도 있는지만 확인(토이 앱엔 HTML 폼이 없어 항상 GET).
# → 이 케이스는 폼이 있는 임의 앱을 대상으로 해야 의미가 있음. 여기선 파서 동작만 간접 확인.
from discover import _LinkParser
_p = _LinkParser()
_p.feed('<form method="POST" action="/x"><input name="u"></form>')
post_found = any(m == "POST" for _, m, _ in _p.forms)
ok = post_found
all_ok = all_ok and ok
print(("[PASS]" if ok else "[FAIL]"), "Discover 폼 POST 인식".ljust(26),
      "post후보:%s" % post_found, "(기대: True)")

print("=" * 56)
print("전체 결과:", "PASS — 전부 통과" if all_ok else "FAIL — 문제 있음")
srv.shutdown()