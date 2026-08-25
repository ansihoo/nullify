"""
Nullify 최소 데모: 취약 앱을 로컬에 띄우고 → 검증기로 두 엔드포인트를 찔러본다.
한 번에 실행:  python demo.py
"""
from vuln_app import serve_in_thread
from verify_sqli import verify


def show(title, url, expect):
    verdict, reason, ev = verify(url)
    ok = "[OK]" if verdict == expect else "[MISMATCH!]"
    print("=" * 70)
    print("[%s]  %s" % (title, url))
    print("  판정 : %-14s  기대: %-14s  %s" % (verdict, expect, ok))
    print("  근거 : %s" % reason)
    print("  ── 증거(재현 가능한 응답) ──")
    for k, v in ev.items():
        print("    %-26s -> %s" % (k, v.replace("\n", " / ")))
    print()


if __name__ == "__main__":
    srv = serve_in_thread(8009)
    base = "http://127.0.0.1:8009"
    print("타깃(일부러 취약한 앱) 로컬 실행:", base, "\n")

    show("취약 엔드포인트", base + "/user",      "CONFIRMED")
    show("안전 엔드포인트", base + "/user_safe", "FALSE_POSITIVE")

    srv.shutdown()
    print("데모 종료 — 판정에 LLM 은 전혀 개입하지 않았다. 전부 응답 차분으로 결정.")
