"""
완전체 결합 — SAST(정적) + DAST(동적) 신호를 하나로 합쳐 '증거 등급'을 매긴다.

정직한 한계:
  소스 위치(app.js:653)를 자동으로 런타임 트리거(POST /x?p=payload)로 바꾸는 건
  임의 앱에선 불가능하다. 그래서 '취약점 종류(kind)'로 두 신호를 상관시킨다(coarse but honest).

증거 등급:
  static+dynamic : Semgrep 도 찾고, 우리가 실제로 재현도 함 → 가장 강함
  dynamic        : 우리가 찔러서 확정(정적엔 없음)
  static-only    : Semgrep 은 찾았으나 DAST 가 도달/확정 못 함 → 배포·수동 검증 필요(정직한 갭)
"""

# Semgrep 의 장황한 종류명 → 우리 kind 로 정규화 (구체적인 것부터)
KIND_WORDS = [
    ("command", "cmdi"), ("rce", "cmdi"),
    ("xss", "xss"), ("cross-site", "xss"),
    ("sql", "sqli"),
    ("traversal", "traversal"), ("lfi", "traversal"), ("path", "traversal"),
    ("ssrf", "ssrf"),
    ("redirect", "redirect"),
    ("secret", "secret"), ("credential", "secret"),
]

ACTIVE = {"critical", "warn", "question"}   # DAST 에서 '조치 필요' = 동적 히트


def normalize_kind(s):
    s = (s or "").lower()
    for word, kind in KIND_WORDS:
        if word in s:
            return kind
    return s or "other"


def combine(dast_findings, sast_findings):
    # 동적: kind 별 '활성(active)' 핀딩 하나
    dmap = {}
    for f in dast_findings:
        if f.get("severity") in ACTIVE:
            dmap.setdefault(f.get("kind"), f)
    # 정적: kind 정규화해 모음
    smap = {}
    for f in sast_findings:
        smap.setdefault(normalize_kind(f.get("kind")), []).append(f)

    combined = []
    for k in sorted(set(dmap) | set(smap)):
        d = dmap.get(k)
        s = smap.get(k, [])
        evidence = "static+dynamic" if (d and s) else ("dynamic" if d else "static-only")
        combined.append({
            "kind": k,
            "evidence": evidence,
            "dast": ({"type": d.get("type"), "endpoint": d.get("endpoint"),
                      "verdict": d.get("verdict")} if d else None),
            "sast": [{"file": x.get("file"), "line": x.get("line"),
                      "message": x.get("message", "")} for x in s],
        })

    summary = {"static+dynamic": 0, "dynamic": 0, "static-only": 0}
    for c in combined:
        summary[c["evidence"]] += 1
    return {"combined": combined, "summary": summary}


if __name__ == "__main__":
    dast = [{"kind": "xss", "type": "Reflected XSS", "endpoint": "/search",
             "verdict": "CONFIRMED", "severity": "critical"},
            {"kind": "sqli", "type": "SQL Injection", "endpoint": "/user",
             "verdict": "CONFIRMED", "severity": "critical"}]
    sast = [{"kind": "Cross-Site-Scripting (XSS)", "file": "app.js", "line": 653, "message": "innerHTML"},
            {"kind": "secret", "file": "config.py", "line": 3, "message": "AWS key"}]
    import json
    print(json.dumps(combine(dast, sast), ensure_ascii=False, indent=2))
