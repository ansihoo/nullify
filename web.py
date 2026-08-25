"""
Nullify 웹 스켈레톤 (버릴 수 있는 최소본).
- 브라우저에서 'URL 입력 → 검사 → 3-way 랭킹 + 영수증 + 질문' 흐름 확인용.
- 디자인은 팀 화면으로 교체 예정 → 스타일 최소. 표준 라이브러리만.

3-way 랭킹:
  critical  = 지금 진짜 터짐 (SQLi, XSS)        → 영수증
  question  = 질문하면 확정 (IDOR)              → 개발자에게 질문 → 답 → 확정/기각
  info      = 참고 (안전판)

실행:  python web.py   → http://127.0.0.1:8000

능동 검증기(sqli/xss/cmdi/traversal/redirect/ssrf)는 GET/POST 둘 다 검증한다.
discover 가 폼에서 발견한 method(GET/POST) 를 run_scan 이 후보에서 읽어 검증기까지 전달.
수동/특수(secret/headers/component/idor) 는 method 개념이 없어 GET 으로 고정.
"""
import json
import inspect
import difflib
import http.server
import urllib.parse

# 엔진은 과녁(vuln_app)을 import 하지 않는다 — 오직 HTTP 로만 대화(진짜 외부 스캐너처럼).
from verifiers.verify_sqli import verify as verify_sqli
from verifiers.verify_xss import verify as verify_xss
from verifiers.verify_idor import cross_account_test, enumerate_test
from verifiers.verify_traversal import verify as verify_traversal
from verifiers.verify_cmdi import verify as verify_cmdi
from verifiers.verify_redirect import verify as verify_redirect
from verifiers.verify_ssrf import verify as verify_ssrf
from verifiers.verify_headers import verify as verify_headers
from verifiers.verify_secret import verify as verify_secret
from verifiers.verify_component import verify as verify_component
from verifiers.exploit_sqli import find_column_count, union_extract
from ingest import load_candidates
from authorize import authorize
from fixes import FIXES
import scanner
import sast
import combine
import github_pr
import store
import notify
from collections import deque
import os
import sys
import time
import threading
import traceback
import subprocess
import urllib.request

TARGET_BASE = os.environ.get("NULLIFY_TARGET", "http://127.0.0.1:8009")


def _reachable(base):
    try:
        urllib.request.urlopen(base + "/app", timeout=1)
        return True
    except Exception:
        return False


def ensure_demo_target():
    """데모 편의: 외부 타깃이 안 떠 있으면 취약 과녁을 '별도 프로세스'로 띄운다.
       엔진은 과녁을 import 하지 않고 HTTP 로만 대화한다. 실제 배포에선 이 spawn 을 끈다."""
    if _reachable(TARGET_BASE):
        return
    here = os.path.dirname(os.path.abspath(__file__))
    subprocess.Popen(["python", os.path.join(here, "vuln_app.py")], cwd=here,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(25):
        if _reachable(TARGET_BASE):
            return
        time.sleep(0.2)


ensure_demo_target()

# ① 후보는 이제 '스캐너 리포트'에서 온다(하드코딩 아님). 데모용 Nuclei 스타일 샘플.
REPORT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner_report.jsonl")
CANDIDATES = load_candidates(REPORT)

# 수정 PR 을 만들 데모 레포(사용자 레포 대역). 시작 시 준비.
SAMPLE_REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_repo")
github_pr.ensure_repo(SAMPLE_REPO)

store.init_db()   # 스캔 이력 저장소 준비

RANK = {"critical": 0, "question": 1, "warn": 2, "info": 3}


def control(base, vuln, mode):
    """타깃의 /control 로 '패치 배포(safe)/원복(vuln)'을 HTTP 로 지시.
       엔진이 과녁 코드를 직접 만지지 않는다 — CI 재배포의 대역."""
    try:
        urllib.request.urlopen(base + "/control?vuln=%s&mode=%s" % (vuln, mode), timeout=3).read()
    except Exception:
        pass


def patch_for(kind):
    """수정 카탈로그(fixes.py)에서 before→after unified diff 를 만든다(엔진은 코드를 모름)."""
    spec = FIXES.get(kind)
    if not spec:
        return None
    return "".join(difflib.unified_diff(
        spec["before"].splitlines(keepends=True), spec["after"].splitlines(keepends=True),
        fromfile="app.py (취약)", tofile="app.py (패치 · PR)"))


def secrets_from(body):
    return [ln.split(",")[0] for ln in body.splitlines() if "-secret" in ln]


def scan_sqli(base, path, param="id", method="GET"):
    # 공격 재현(union_extract, find_column_count)도 method 로 — POST 폼 SQLi 는 POST 로 탈취.
    url = base + path
    v, reason, _ = verify_sqli(url, param, method=method)
    f = {"type": "SQL Injection", "endpoint": path, "verdict": v, "reason": reason, "method": method}
    if v != "CONFIRMED":
        f["severity"] = "info"
        return f
    find_column_count(url, param, method=method)
    _, body = union_extract(url, "secret, name FROM users", param, method=method)
    before = secrets_from(body)
    patch = patch_for("sqli")
    control(base, "sqli", "safe")                      # 패치 배포(= CI 재배포 대역)
    va, _, _ = verify_sqli(url, param, method=method)
    _, body_a = union_extract(url, "secret, name FROM users", param, method=method)
    after = secrets_from(body_a)
    control(base, "sqli", "vuln")                      # 데모 반복 위해 원복
    f.update(severity="critical", proof_label="훔친 secret", proof=before, patch=patch,
             receipt={"before": {"verdict": v, "count": len(before)},
                      "after": {"verdict": va, "count": len(after)},
                      "fixed": va == "FALSE_POSITIVE" and len(after) == 0})
    return f


def scan_xss(base, path, param="q", method="GET"):
    url = base + path
    v, reason, ev = verify_xss(url, param, method=method)
    f = {"type": "Reflected XSS", "endpoint": path, "verdict": v, "reason": reason, "method": method}
    if v != "CONFIRMED":
        f["severity"] = "info"
        return f
    patch = patch_for("xss")
    control(base, "xss", "safe")
    va, _, _ = verify_xss(url, param, method=method)
    control(base, "xss", "vuln")
    f.update(severity="critical", proof_label="반사된 실행형 페이로드",
             proof=[ev.get("reflected_raw", "")], patch=patch,
             receipt={"before": {"verdict": v, "count": 1},
                      "after": {"verdict": va, "count": (1 if va == "CONFIRMED" else 0)},
                      "fixed": va == "FALSE_POSITIVE"})
    return f


def scan_traversal(base, path, param="file", method="GET"):
    url = base + path
    v, reason, ev = verify_traversal(url, param, method=method)
    f = {"type": "Path Traversal", "endpoint": path, "verdict": v, "reason": reason, "method": method}
    if v != "CONFIRMED":
        f["severity"] = "info"
        return f
    patch = patch_for("traversal")
    control(base, "traversal", "safe")
    va, _, _ = verify_traversal(url, param, method=method)
    control(base, "traversal", "vuln")
    f.update(severity="critical", proof_label="유출된 파일 내용",
             proof=[ev.get("response", "")], patch=patch,
             receipt={"before": {"verdict": v, "count": 1},
                      "after": {"verdict": va, "count": (0 if va == "FALSE_POSITIVE" else 1)},
                      "fixed": va == "FALSE_POSITIVE"})
    return f


def _receipt(before_v, after_v):
    return {"before": {"verdict": before_v, "count": 1},
            "after": {"verdict": after_v, "count": (1 if after_v == "CONFIRMED" else 0)},
            "fixed": after_v == "FALSE_POSITIVE"}


def scan_cmdi(base, path, param="host", method="GET"):
    url = base + path
    v, reason, ev = verify_cmdi(url, param, method=method)
    f = {"type": "Command Injection", "endpoint": path, "verdict": v, "reason": reason, "method": method}
    if v != "CONFIRMED":
        f["severity"] = "info"
        return f
    patch = patch_for("cmdi")
    control(base, "cmdi", "safe"); va, _, _ = verify_cmdi(url, param, method=method); control(base, "cmdi", "vuln")
    f.update(severity="critical", proof_label="실행 증거", proof=[ev.get("response", "")],
             patch=patch, receipt=_receipt(v, va))
    return f


def scan_redirect(base, path, param="next", method="GET"):
    url = base + path
    v, reason, ev = verify_redirect(url, param, method=method)
    f = {"type": "Open Redirect", "endpoint": path, "verdict": v, "reason": reason, "method": method}
    if v != "CONFIRMED":
        f["severity"] = "info"
        return f
    patch = patch_for("redirect")
    control(base, "redirect", "safe"); va, _, _ = verify_redirect(url, param, method=method); control(base, "redirect", "vuln")
    f.update(severity="critical", proof_label="리다이렉트 대상", proof=[ev.get("location", "")],
             patch=patch, receipt=_receipt(v, va))
    return f


def scan_ssrf(base, path, param="url", method="GET"):
    # verify_ssrf 는 internal_url 이 2번째 인자라 method 는 맨 끝에 붙인다.
    url = base + path
    internal = base + "/internal"
    v, reason, ev = verify_ssrf(url, internal, param, method=method)
    f = {"type": "SSRF", "endpoint": path, "verdict": v, "reason": reason, "method": method}
    if v != "CONFIRMED":
        f["severity"] = "info"
        return f
    patch = patch_for("ssrf")
    control(base, "ssrf", "safe"); va, _, _ = verify_ssrf(url, internal, param, method=method); control(base, "ssrf", "vuln")
    f.update(severity="critical", proof_label="유출된 내부 응답", proof=[ev.get("response", "")],
             patch=patch, receipt=_receipt(v, va))
    return f


def scan_secret(base, path):
    url = base + path
    v, reason, ev = verify_secret(url)
    f = {"type": "Exposed Secret", "endpoint": path, "verdict": v, "reason": reason}
    if v != "CONFIRMED":
        f["severity"] = "info"
        return f
    patch = ("--- config.js\n+++ config.js (권고)\n"
             "- var API_KEY=\"AKIA...\";        // 키를 코드에 하드코딩\n"
             "+ var API_KEY=window.__CFG.key;  // 서버가 런타임에 주입")
    control(base, "secret", "safe"); va, _, _ = verify_secret(url); control(base, "secret", "vuln")
    f.update(severity="critical", proof_label="노출된 키", proof=[ev.get("matched", "")],
             patch=patch, receipt=_receipt(v, va))
    return f


def scan_headers(base, path):
    url = base + path
    v, reason, ev = verify_headers(url)
    f = {"type": "Security Headers", "endpoint": path, "verdict": v, "reason": reason}
    if v != "CONFIRMED":
        f["severity"] = "info"
        return f
    patch = ("--- 응답 헤더\n+++ 응답 헤더 (권고)\n"
             "+ X-Frame-Options: DENY\n+ Content-Security-Policy: default-src 'self'")
    control(base, "headers", "safe"); va, _, _ = verify_headers(url); control(base, "headers", "vuln")
    f.update(severity="warn", proof_label="누락 헤더", proof=[ev.get("missing", "")],
             patch=patch, receipt=_receipt(v, va))
    return f


def scan_component(base, path):
    url = base + path
    v, reason, ev = verify_component(url)
    f = {"type": "Outdated Component", "endpoint": path, "verdict": v, "reason": reason}
    if v != "CONFIRMED":
        f["severity"] = "info"
        return f
    patch = "--- 의존성\n+++ 의존성 (권고)\n- jquery-1.4.2\n+ jquery-3.7.1"
    control(base, "component", "safe"); va, _, _ = verify_component(url); control(base, "component", "vuln")
    f.update(severity="warn", proof_label="탐지 버전", proof=[ev.get("version", "")],
             patch=patch, receipt=_receipt(v, va))
    return f


def scan_idor(base, path="/order", param="id"):
    # 데모 토이 앱(/order)은 알려진 계정 체계로 '강한' 교차계정 증거를 낼 수 있다.
    # 그 외 임의 경로는 인증 없이 관찰 가능한 신호(객체 열거)로 일반화한다.
    if path == "/order":
        leaked, ev = cross_account_test(base)
        reason_yes = "다른 사용자(bob)가 alice 의 주문을 열람할 수 있음 — 이게 문제인지는 '앱의 의도'에 달림"
        question = "이 주문 내역은 '주문한 본인만' 봐야 하나요?"
    else:
        leaked, ev = enumerate_test(base, path, param, "1")
        reason_yes = ("%s 의 %s 를 순차로 옮기면 접근제어 없이 다른 객체가 열람됨(무방비 직접참조) "
                      "— 문제인지는 '이 객체가 비공개여야 하는지'에 달림" % (path, param))
        question = "%s 로 조회되는 이 객체는 '소유자 본인만' 봐야 하나요?" % path
    f = {"type": "IDOR / 접근제어", "endpoint": path, "param": param, "evidence": ev}
    if not leaked:
        f.update(verdict="FALSE_POSITIVE", severity="info",
                 reason="접근제어가 동작하거나 열거 신호 없음")
        return f
    # 관찰은 됐으나 '의도'를 몰라 자동 확정 불가 → 개발자에게 질문
    f.update(verdict="UNKNOWN", severity="question", reason=reason_yes, question=question,
             answers=[{"label": "네, 본인만", "value": "owner_only"},
                      {"label": "아니요, 공개", "value": "public"}])
    return f


def resolve_idor(base, answer, path="/order", param="id"):
    if answer == "public":
        return {"verdict": "FALSE_POSITIVE", "severity": "info", "endpoint": path,
                "reason": "공개 데이터로 확인됨 → 문제 아님. 목록에서 내림."}
    patch = patch_for("idor")
    # 토이 앱(/order): 알려진 계정 체계로 닫힌 루프까지(패치 배포→재확인→죽음 증명).
    if path == "/order":
        _, ev = cross_account_test(base)
        control(base, "idor", "safe")
        leaked_after, _ = cross_account_test(base)
        control(base, "idor", "vuln")
        return {"verdict": "CONFIRMED", "severity": "critical", "endpoint": path,
                "reason": "본인만 봐야 하는데 타인이 열람 가능 → IDOR 확정",
                "proof_label": "유출된 타인 주문", "proof": [ev["응답"]],
                "patch": patch,
                "receipt": {"before": {"verdict": "CONFIRMED", "count": 1},
                            "after": {"verdict": "FALSE_POSITIVE" if not leaked_after else "CONFIRMED",
                                      "count": 0 if not leaked_after else 1},
                            "fixed": not leaked_after}}
    # 임의 경로: 열거 증거로 CONFIRMED 승격. 단 닫힌 루프(패치 후 재검증)는
    # 계정/소유권 컨텍스트가 있어야 자동 증명 가능 → 여기선 정직하게 '미검증'으로 남긴다.
    leaked, ev = enumerate_test(base, path, param, "1")
    proof = [h["응답"] for h in ev.get("열람된_다른객체", [])] or ["(열거 증거 없음)"]
    return {"verdict": "CONFIRMED", "severity": "critical", "endpoint": path,
            "reason": "소유자만 봐야 하는데 순차 id 로 타 객체 열람 가능 → IDOR 확정",
            "proof_label": "무방비로 열람된 다른 객체", "proof": proof,
            "patch": patch,
            "receipt": {"before": {"verdict": "CONFIRMED", "count": 1},
                        "after": {"verdict": "UNVERIFIED", "count": 1},
                        "fixed": False,
                        "note": "재검증(패치 후 죽음 증명)엔 인증/소유권 컨텍스트 필요 — 자동 닫힌루프 불가."}}


SCANNERS = {
    # 능동 검증기: 4번째 인자 m(method) 을 실제로 전달(GET/POST 자동 인지).
    "sqli": lambda b, p, pr, m="GET": scan_sqli(b, p, pr or "id", method=m),
    "xss": lambda b, p, pr, m="GET": scan_xss(b, p, pr or "q", method=m),
    "traversal": lambda b, p, pr, m="GET": scan_traversal(b, p, pr or "file", method=m),
    "cmdi": lambda b, p, pr, m="GET": scan_cmdi(b, p, pr or "host", method=m),
    "redirect": lambda b, p, pr, m="GET": scan_redirect(b, p, pr or "next", method=m),
    "ssrf": lambda b, p, pr, m="GET": scan_ssrf(b, p, pr or "url", method=m),
    # 수동/특수: method 개념이 없어 m 을 받되 무시(파라미터 payload 를 안 쓰거나 고정 시나리오).
    "secret": lambda b, p, pr, m="GET": scan_secret(b, p),
    "headers": lambda b, p, pr, m="GET": scan_headers(b, p),
    "component": lambda b, p, pr, m="GET": scan_component(b, p),
    "idor": lambda b, p, pr, m="GET": scan_idor(b, p or "/order", pr or "id"),
}


def _active(f):
    # '조치가 필요한' 상태 = 진짜 터짐/질문/경고. info(오탐·안전)는 해소된 것.
    return f.get("severity") in ("critical", "warn", "question")


def compare_findings(old, new):
    """이전 스캔 대비 변화를 (kind,endpoint) 기준으로 분류: 고쳐짐/새로생김/그대로."""
    def key(f):
        return (f.get("kind"), f.get("endpoint"))
    old_map = {key(f): f for f in old}
    new_map = {key(f): f for f in new}
    old_active = {k for k, f in old_map.items() if _active(f)}
    new_active = {k for k, f in new_map.items() if _active(f)}

    def label(k):
        f = new_map.get(k) or old_map.get(k) or {}
        return "%s %s" % (f.get("type") or k[0], k[1])

    return {
        "fixed":     [label(k) for k in sorted(old_active - new_active)],
        "new":       [label(k) for k in sorted(new_active - old_active)],
        "unchanged": [label(k) for k in sorted(old_active & new_active)],
    }


def run_scan(base, prefer_discover=False):
    candidates, source = scanner.candidates_for(base, prefer_discover)   # ① 실 Nuclei / 내장 크롤러 / 샘플
    findings = []
    for c in candidates:
        fn = SCANNERS.get(c["kind"])
        if fn:
            # 후보에 method 가 있으면(폼 발견 시 POST 등) 그걸로, 없으면 GET.
            f = fn(base, c["path"], c.get("param", ""), c.get("method", "GET"))
        else:                                  # 검증기 없는 종류는 정직하게 UNKNOWN
            f = {"type": c["kind"], "endpoint": c["path"], "verdict": "UNKNOWN",
                 "severity": "info", "reason": "이 종류의 검증기가 아직 없음"}
        f["scanner"] = c.get("scanner", "")    # 스캐너의 원래 주장(오탐 대비용)
        f["kind"] = c["kind"]                  # 수정 PR 생성 시 어떤 패치인지
        f.setdefault("method", c.get("method", "GET"))   # 어떤 방식으로 검증했는지 기록(표시용)
        findings.append(f)
    findings.sort(key=lambda x: RANK.get(x["severity"], 9))
    crit = sum(1 for f in findings if f["severity"] == "critical")
    ques = sum(1 for f in findings if f["severity"] == "question")
    warn = sum(1 for f in findings if f["severity"] == "warn")
    return {"target": base, "total": len(findings), "crit": crit, "ques": ques,
            "warn": warn, "findings": findings, "candidate_source": source}


PAGE = r"""<!doctype html><html lang=ko><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Nullify — 취약점 검증 콘솔</title>
<style>
 :root{--bg:#f4f6f8;--side:#161b26;--ink:#1a1f2b;--muted:#6b7480;--line:#e2e6ec;--acc:#0d7680}
 *{box-sizing:border-box}
 body{margin:0;font:15px/1.6 system-ui,"Malgun Gothic",sans-serif;color:var(--ink);background:var(--bg);display:flex;min-height:100vh}
 aside{width:210px;background:var(--side);color:#c9d2de;flex:none;display:flex;flex-direction:column;padding:18px 0}
 aside .brand{font-size:20px;font-weight:700;color:#fff;padding:0 20px 16px}
 aside .brand span{color:#3bb4c0}
 nav a{display:block;padding:10px 20px;color:#aab3c0;cursor:pointer;font-size:14px;border-left:3px solid transparent}
 nav a:hover{background:#1e2533;color:#fff}
 nav a.active{background:#1e2533;color:#fff;border-left-color:#3bb4c0}
 main{flex:1;min-width:0;padding:24px clamp(16px,4vw,40px);max-width:980px}
 header.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:8px}
 header.top h1{font-size:22px;margin:0}
 .pill{font:12px monospace;padding:3px 9px;border-radius:999px;background:#e6ecf2;color:#3a5570}
 .pill.ok{background:#d6efe2;color:#1c8a5b} .pill.off{background:#f1e5cd;color:#a8701a}
 .pill a{color:inherit}
 .view{display:none}
 .lead{color:var(--muted);font-size:14px;margin:0 0 16px}
 .bar{display:flex;gap:8px;flex-wrap:wrap}
 input{flex:1;min-width:180px;padding:9px 11px;border:1px solid #ccc;border-radius:8px;font:inherit}
 button{padding:8px 14px;border:0;border-radius:8px;background:var(--acc);color:#fff;font:inherit;cursor:pointer}
 button.sec{background:#4a6b8a} button.vio{background:#6a5acd} button.dk{background:#333}
 button.ans{background:#fff;border:1px solid #a8701a;color:#a8701a;margin-right:8px}
 .sum{margin:16px 0;font-weight:600}
 .card{border:1px solid #e0e0e0;border-radius:10px;padding:14px 16px;margin:10px 0;background:#fff}
 .crit{border-left:4px solid #c0392b} .question{border-left:4px solid #a8701a}
 .warn{border-left:4px solid #4a6b8a} .info{border-left:4px solid #aaa;opacity:.85}
 .hist{border:1px solid #e6e6e6;border-radius:8px;padding:8px 11px;margin:6px 0;font-size:13px;cursor:pointer;background:#fff}
 .hist:hover{background:#f0f4f8}
 .tag{font:12px monospace;padding:1px 7px;border-radius:999px}
 .t-crit{background:#f7ded9;color:#c0392b} .t-q{background:#f1e5cd;color:#a8701a}
 .t-warn{background:#dde6ef;color:#3a5570} .t-info{background:#eee;color:#666}
 .receipt{background:#f6f8f8;border-radius:8px;padding:10px 12px;margin-top:10px;font-size:13px}
 pre{background:#0d1117;color:#d6dee8;padding:12px;border-radius:8px;overflow-x:auto;font-size:12px}
 .del{color:#ff9492} .add{color:#7ee2a8}
 .stats{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0 20px}
 .stat{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:120px}
 .stat b{display:block;font-size:24px} .stat span{color:var(--muted);font-size:12px}
 @media(max-width:640px){body{flex-direction:column}aside{width:auto;flex-direction:row;overflow-x:auto;padding:8px}aside .brand{display:none}nav{display:flex}nav a{border-left:0;border-bottom:3px solid transparent;white-space:nowrap}}
</style></head><body>
<aside>
 <div class=brand>Null<span>ify</span></div>
 <nav>
  <a data-v=dashboard onclick="show('dashboard')">대시보드</a>
  <a data-v=scan onclick="show('scan')">동적 검사</a>
  <a data-v=source onclick="show('source')">정적 검사</a>
  <a data-v=combined onclick="show('combined')">통합 검사</a>
  <a data-v=history onclick="show('history')">이력</a>
  <a data-v=alerts onclick="show('alerts')">알림</a>
 </nav>
</aside>
<main>
 <header class=top><h1 id=vtitle>대시보드</h1><div><span id=authstate class=pill></span> <span id=hstat class=pill>…</span></div></header>

 <section id=view-dashboard class=view>
  <p class=lead>실행 중인 앱(DAST)과 소스코드(SAST)를 검증해 '진짜 터지는' 취약점만 골라냅니다.</p>
  <div class=stats id=dash></div>
  <div class=bar><button onclick="show('scan')">동적 검사</button><button class=vio onclick="show('source')">정적 검사</button><button class=dk onclick="show('combined')">통합 검사</button></div>
 </section>

 <section id=view-scan class=view>
  <p class=lead>실행 중인 앱을 실제로 찔러 검증합니다. 재검증은 이전 스캔과 비교해 추세를 봅니다.</p>
  <div class=bar><input id=t value="__TARGET__"><button onclick=scan()>검사</button><button class=sec onclick=rescan()>재검증</button></div>
  <label style="display:block;margin:-4px 0 8px;font-size:13px;color:#555"><input type=checkbox id=disco> 내장 크롤러로 후보 자동발견 <span style="color:#888">(외부 스캐너 없이 임의 앱 대상 — 크롤+탐침으로 엔드포인트 찾기)</span></label>
  <div id=out></div>
 </section>

 <section id=view-source class=view>
  <p class=lead>깃허브 레포/경로를 클론해 소스를 정적 분석(SAST)합니다. Semgrep 있으면 실행, 없으면 시크릿 스캔.</p>
  <div class=bar><input id=repo placeholder="GitHub 레포 URL 또는 경로"><button class=vio onclick=scanSource()>소스 검사</button></div>
  <div id=sout></div>
 </section>

 <section id=view-combined class=view>
  <p class=lead>URL(동적) + 레포(정적)를 함께 검사해, 각 취약점에 증거 등급(정적+동적 / 동적 / 정적만)을 매깁니다.</p>
  <div class=bar><input id=ct value="__TARGET__" placeholder="대상 URL"><input id=crepo placeholder="레포 URL/경로"><button class=dk onclick=scanCombined()>통합 검사</button></div>
  <div id=cout></div>
 </section>

 <section id=view-history class=view>
  <p class=lead>저장된 스캔 이력. 항목을 누르면 그 결과를 다시 봅니다.</p>
  <div id=history></div>
 </section>

 <section id=view-alerts class=view>
  <p class=lead>재검증에서 '새로 생긴' 취약점(리그레션) 알림.</p>
  <div id=alerts></div>
 </section>
</main>
<script>
const TITLES={dashboard:'대시보드',scan:'동적 검사',source:'정적 검사',combined:'통합 검사',history:'이력',alerts:'알림'};
function show(v){
 v=v||'dashboard';
 document.querySelectorAll('.view').forEach(x=>x.style.display='none');
 const el=document.getElementById('view-'+v); if(!el){v='dashboard';document.getElementById('view-dashboard').style.display='block';}
 else el.style.display='block';
 document.querySelectorAll('nav a').forEach(a=>a.classList.toggle('active',a.dataset.v===v));
 document.getElementById('vtitle').textContent=TITLES[v]||'';
 if(location.hash.slice(1)!==v) location.hash=v;
 if(v==='history')loadHistory(); if(v==='alerts')loadAlerts(); if(v==='dashboard')loadDashboard();
}
window.addEventListener('hashchange',()=>show(location.hash.slice(1)));
function stat(v,l){return '<div class=stat><b>'+esc(String(v))+'</b><span>'+esc(l)+'</span></div>'}
async function pollHealth(){
 try{ const d=await(await fetch('/healthz')).json(); const el=document.getElementById('hstat');
  el.textContent=d.target_reachable?'타깃 정상':'타깃 끊김'; el.className='pill '+(d.target_reachable?'ok':'off'); }catch(e){}
}
async function loadDashboard(){
 try{
  const d=await(await fetch('/healthz')).json();
  let scans=[]; try{ scans=(await(await api('/api/history?limit=200')).json()).scans||[]; }catch(e){}
  document.getElementById('dash').innerHTML=
   stat(scans.length,'저장된 스캔')+stat(d.verifiers.length,'검증기')+
   stat(d.scanner.nuclei_available?'ON':'OFF','Nuclei')+
   stat(d.auth_mode,'인증 모드')+stat(d.target_reachable?'정상':'끊김','타깃 상태');
 }catch(e){}
}
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function getToken(){return localStorage.getItem('nullify_token')||''}
function setToken(t){localStorage.setItem('nullify_token',t)}
function clearToken(){localStorage.removeItem('nullify_token');checkAuth()}
function askToken(){const t=prompt('API 토큰을 입력하세요:');if(t){setToken(t);checkAuth();}}
async function api(path){
 let r=await fetch(path, getToken()?{headers:{'X-API-Token':getToken()}}:{});
 if(r.status===401){ const t=prompt('API 토큰이 필요합니다:'); if(t){setToken(t);checkAuth();r=await fetch(path,{headers:{'X-API-Token':t}});} }
 return r;
}
async function checkAuth(){
 try{ const d=await (await fetch('/healthz')).json();
  const el=document.getElementById('authstate'); if(!el) return;
  el.innerHTML = !d.auth ? '' :
   (getToken()?'🔒 인증됨 · <a href=# onclick="clearToken();return false">토큰 해제</a>'
             :'<a href=# onclick="askToken();return false">🔒 API 토큰 입력 필요</a>');
 }catch(e){}
}
function diff(p){return esc(p).split('\n').map(l=>{
 if(l.startsWith('+'))return '<span class=add>'+l+'</span>';
 if(l.startsWith('-'))return '<span class=del>'+l+'</span>'; return l;}).join('\n')}
function receiptHtml(label, proof, R){
 let h='<div class=receipt>'+esc(label)+': <b>'+esc((proof||[]).join(', '))+'</b><br>';
 h+='영수증 — before: '+R.before.verdict+' ('+R.before.count+') → after: '
   +R.after.verdict+' ('+R.after.count+') '
   +(R.fixed?'<b style=color:#1c8a5b>✔ 소멸 확인</b>':'');
 return h+'</div>';
}
function renderResult(d){
 window.LAST=d;
 const out=document.getElementById('out');
 if(d.authorized===false){ out.innerHTML=
   '<div class="card crit"><b>스캔 거부됨</b><div style=color:#666;margin-top:4px>'+esc(d.reason)+'</div>'
   +'<div style=color:#999;font-size:12px;margin-top:6px>허가된 대상(로컬/사설망, 또는 소유권이 증명된 자산)만 스캔합니다.</div></div>';
   return; }
 const dis=d.total-d.crit-d.ques-d.warn;
 let h='<div class=sum>스캐너['+esc(d.candidate_source||'?')+'] 후보 '+d.total+'개 → 진짜 터짐 '+d.crit+' · 질문하면 확정 '+d.ques+' · 경고 '+d.warn+' · 걸러낸 오탐 '+dis
   +(d.scan_id?' <span style="color:#999;font-size:12px">(#'+d.scan_id+' 저장됨)</span>':'')+'</div>';
 if(d.compare){ const C=d.compare;
  h+='<div class=sum style="font-size:14px">재검증 (이전 #'+C.prev_id+' 대비): 고쳐짐 '+C.fixed.length+' · 새로 생김 '+C.new.length+' · 그대로 '+C.unchanged.length+'</div>';
  if(C.fixed.length) h+='<div class=receipt style="border-left:3px solid #1c8a5b">✔ 고쳐짐: '+esc(C.fixed.join(', '))+'</div>';
  if(C.new.length) h+='<div class=receipt style="border-left:3px solid #c0392b">⚠ 새로 생김: '+esc(C.new.join(', '))+'</div>';
 }
 d.findings.forEach((f,i)=>{ h+='<div class="card '+f.severity+'" id="c'+i+'">'+cardHtml(f,i)+'</div>'; });
 out.innerHTML=h;
}
function discoFlag(){ return document.getElementById('disco') && document.getElementById('disco').checked ? '&discover=1' : ''; }
async function scan(){
 document.getElementById('out').innerHTML='검사 중…';
 const r=await api('/api/scan?target='+encodeURIComponent(document.getElementById('t').value)+discoFlag());
 renderResult(await r.json());
 loadHistory();
}
async function rescan(){
 document.getElementById('out').innerHTML='재검증 중… (이전 스캔과 비교)';
 const r=await api('/api/rescan?target='+encodeURIComponent(document.getElementById('t').value)+discoFlag());
 renderResult(await r.json());
 loadHistory(); loadAlerts();
}
function evLabel(e){return {'static+dynamic':'🟣🔴 정적+동적 (가장 강함)','dynamic':'🔴 동적 확인','static-only':'🟣 정적만 (미검증 — 배포/수동 필요)'}[e]||e}
async function scanCombined(){
 const t=document.getElementById('ct').value, s=document.getElementById('crepo').value;
 const el=document.getElementById('cout'); el.innerHTML='통합 검사 중… (동적 DAST + 정적 SAST)';
 const r=await api('/api/scan_combined?target='+encodeURIComponent(t)+'&source='+encodeURIComponent(s));
 const d=await r.json();
 if(d.authorized===false){ el.innerHTML='<div class=receipt style=color:#c0392b>스캔 거부: '+esc(d.reason)+'</div>'; return; }
 const S=d.summary;
 let h='<div class=sum>통합 [SAST:'+esc(d.sast_scanner)+'] — 정적+동적 '+S['static+dynamic']+' · 동적확인 '+S.dynamic+' · 정적만 '+S['static-only']+'</div>';
 if(!d.combined.length) h+='<div style=color:#999>상관된 항목 없음</div>';
 d.combined.forEach(c=>{
  const col=c.evidence==='static+dynamic'?'#c0392b':(c.evidence==='dynamic'?'#c0392b':'#6a5acd');
  h+='<div class=receipt style="border-left:3px solid '+col+'"><b>'+esc(c.kind)+'</b> — '+evLabel(c.evidence);
  if(c.dast) h+='<br>동적: '+esc(c.dast.type)+' <code>'+esc(c.dast.endpoint)+'</code> ['+esc(c.dast.verdict)+']';
  c.sast.forEach(x=>{ h+='<br>정적: <code>'+esc(x.file)+':'+esc(x.line)+'</code> '+esc(x.message||''); });
  h+='</div>';
 });
 el.innerHTML=h;
}
async function scanSource(){
 const s=document.getElementById('repo').value; if(!s) return;
 const el=document.getElementById('sout'); el.innerHTML='소스 분석 중… (clone + SAST)';
 const r=await api('/api/scan_source?source='+encodeURIComponent(s));
 const d=await r.json();
 if(d.error){ el.innerHTML='<div class=receipt style="color:#c0392b">'+esc(d.error)+'</div>'; return; }
 let h='<div class=sum>정적 탐지 ['+esc(d.scanner)+'] '+d.findings.length+'건 '
   +'<span style="color:#999;font-size:12px">(미검증 — 실행 앱에서 재현해야 확정)</span></div>';
 if(!d.findings.length) h+='<div style=color:#999>탐지된 정적 이슈 없음</div>';
 d.findings.forEach(f=>{ h+='<div class=receipt style="border-left:3px solid #6a5acd">'
   +'<code>'+esc(f.file)+':'+esc(f.line)+'</code> <span style="color:#6a5acd">['+esc(f.kind)+']</span> '
   +esc(f.message||f.rule)+'</div>'; });
 el.innerHTML=h;
}
async function loadAlerts(){
 const r=await api('/api/notifications?limit=8'); const d=await r.json();
 if(!d.notifications||!d.notifications.length){ document.getElementById('alerts').innerHTML=''; return; }
 let h='<div class=sum style="margin-top:22px">알림 (리그레션)</div>';
 d.notifications.forEach(n=>{ h+='<div class=receipt style="border-left:3px solid #c0392b;font-size:13px">'+esc(n.ts)+' · '+esc(n.message)+'</div>'; });
 document.getElementById('alerts').innerHTML=h;
}
async function deployFix(kind){
 await api('/api/deploy?target='+encodeURIComponent(document.getElementById('t').value)+'&kind='+encodeURIComponent(kind)+'&mode=safe');
 alert(kind+' 를 고친 상태로 배포했습니다(데모). 이제 [재검증] 을 누르면 추적 결과에 반영됩니다.');
}
async function loadHistory(){
 const r=await api('/api/history?limit=15'); const d=await r.json();
 let h='<div class=sum style="margin-top:22px">스캔 이력</div>';
 if(!d.scans.length){ h+='<div style=color:#999>아직 없음</div>'; }
 d.scans.forEach(s=>{
  h+='<div class=hist onclick="showScan('+s.id+')">#'+s.id+' · '+esc(s.ts)+' · <code>'+esc(s.target)+'</code>'
    +' — 진짜 '+s.crit+' · 질문 '+s.ques+' · 경고 '+s.warn+' · 오탐 '+s.dismissed+'</div>';
 });
 document.getElementById('history').innerHTML=h;
}
async function showScan(id){
 const r=await api('/api/scan_detail?id='+id); const d=await r.json();
 if(d.error){ return; }
 show('scan'); renderResult(d); window.scrollTo(0,0);
}
function cardHtml(f,i){
 const cls=f.severity==='critical'?'t-crit':(f.severity==='question'?'t-q':(f.severity==='warn'?'t-warn':'t-info'));
 let h='<b>'+esc(f.type)+'</b> <code>'+esc(f.endpoint)+'</code> <span class="tag '+cls+'">'+f.verdict+'</span>';
 if(f.method&&f.method!=='GET') h+=' <span class="tag t-info">'+esc(f.method)+'</span>';
 if(f.scanner) h+='<div style=color:#999;font-size:12px;margin-top:2px>스캐너 주장: '+esc(f.scanner)+(f.verdict==='FALSE_POSITIVE'?' → 우리 검증: 오탐, 걸러냄':'')+'</div>';
 h+='<div style=color:#666;font-size:13px;margin-top:4px>'+esc(f.reason)+'</div>';
 if(f.severity==='critical'||f.severity==='warn'){
  h+=receiptHtml(f.proof_label,f.proof,f.receipt)+'<pre>'+diff(f.patch)+'</pre>';
  h+='<button onclick="prCreate('+i+')">수정 PR 생성 (실제 git)</button>'
    +'<button onclick="deployFix(\''+(f.kind||'')+'\')" style="background:#888;margin-left:6px">고친 상태로 배포(데모)</button>'
    +'<div id=pr'+i+'></div>';
 }else if(f.severity==='question'){
  const e=f.evidence||{};
  if(e['요청자']){  // 토이 교차계정 증거
   h+='<div class=receipt>근거 — '+esc(e['요청자'])+' 가 '+esc(e['대상'])+' 열람: <code>'+esc(e['응답'])+'</code></div>';
  }else{           // 임의 경로 객체열거 증거
   const objs=(e['열람된_다른객체']||[]).map(o=>'id='+esc(o.id)+': '+esc((o['응답']||'').slice(0,120))).join('<br>');
   h+='<div class=receipt>근거 — '+esc(e['설명']||'순차 id 로 다른 객체 열람')+'<br><code>'+objs+'</code></div>';
  }
  h+='<div style=margin-top:10px><b>'+esc(f.question)+'</b></div><div style=margin-top:8px>';
  f.answers.forEach(a=>{ h+='<button class=ans onclick="resolve('+i+',\''+a.value+'\')">'+esc(a.label)+'</button>'; });
  h+='</div>';
 }
 return h;
}
async function prCreate(i){
 const f=window.LAST.findings[i];
 const box=document.getElementById('pr'+i); box.innerHTML='git 브랜치·커밋 생성 중…';
 const r=await api('/api/pr?kind='+encodeURIComponent(f.kind||''));
 const d=await r.json();
 if(d.error){ box.innerHTML='<div class=receipt style="color:#a8701a">'+esc(d.error)+'</div>'; return; }
 if(d.needs_review){ box.innerHTML='<div class=receipt style="color:#a8701a"><b>전문가 검토 필요</b><br>'
   +esc(d.reason)+'<br><span style="color:#999;font-size:12px">임의 코드 수정은 ANTHROPIC_API_KEY 설정 시 LLM 이 도출합니다.</span></div>'; return; }
 const srcLabel={catalog:'결정론 규칙',llm:'LLM 생성'}[d.fix_source]||d.fix_source;
 box.innerHTML=
  '<div class=receipt><b>실제 git 커밋 생성됨</b> <span style="color:#0d7680;font-size:12px">(수정 출처: '+esc(srcLabel)+')</span><br>'
  +'브랜치: <code>'+esc(d.branch)+'</code> · 커밋: <code>'+esc(d.commit)+'</code><br>'
  +'제목: '+esc(d.title)+'<pre>'+diff(d.diff)+'</pre>'
  +'<b>실행 (당신 GitHub 토큰으로)</b><pre>'+esc(d.gh)+'</pre>'
  +'<span style="color:#999;font-size:12px">※ 브랜치·커밋은 로컬에 실제 생성됨. push/PR 만 당신 인증으로.</span></div>';
}
async function resolve(i, ans){
 const f=window.LAST.findings[i]||{};
 const r=await api('/api/resolve?target='+encodeURIComponent(document.getElementById('t').value)+'&answer='+ans
   +'&path='+encodeURIComponent(f.endpoint||'/order')+'&param='+encodeURIComponent(f.param||'id'));
 const d=await r.json();
 const card=document.getElementById('c'+i);
 const cls=d.verdict==='CONFIRMED'?'t-crit':'t-info';
 card.className='card '+d.severity;
 let h='<b>IDOR / 접근제어</b> <code>'+esc(d.endpoint||f.endpoint||'/order')+'</code> <span class="tag '+cls+'">'+d.verdict+'</span>';
 h+='<div style=color:#666;font-size:13px;margin-top:4px>'+esc(d.reason)+'</div>';
 if(d.verdict==='CONFIRMED'){
  window.LAST.findings[i]=Object.assign({type:'IDOR / 접근제어',endpoint:(d.endpoint||f.endpoint||'/order'),kind:'idor'},d);
  h+=receiptHtml(d.proof_label,d.proof,d.receipt)+'<pre>'+diff(d.patch)+'</pre>';
  h+='<button onclick="prCreate('+i+')">수정 PR 생성 (실제 git)</button><div id=pr'+i+'></div>';
 }
 card.innerHTML=h;
}
checkAuth(); pollHealth(); show(location.hash.slice(1) || 'dashboard');   // 초기 라우팅
</script></body></html>"""


# 스캔은 공유 타깃의 /control 을 토글하므로 직렬화(동시 스캔 경합 방지).
# 레포 작업(git)도 sample_repo 상태를 바꾸므로 직렬화.
SCAN_LOCK = threading.Lock()
REPO_LOCK = threading.Lock()

# --- 엔진 인증: /api/* 는 토큰이 설정돼 있으면 요구(X-API-Token 헤더 또는 ?token=) ---
# 배포 필수: 스캐너+git 쓰기 도구를 무방비로 노출하지 않는다. 토큰 미설정 = 개발 모드(열림).
AUTH_TOKEN = os.environ.get("NULLIFY_API_TOKEN", "")

# --- 요청 제한: 스캔 남용/DoS 방지(프로세스 전역 슬라이딩 윈도) ---
RATE_MAX = int(os.environ.get("NULLIFY_RATE_MAX", "30"))   # 60초당 최대 스캔 수
_rate = deque()
_rate_lock = threading.Lock()


def rate_ok():
    now = time.time()
    with _rate_lock:
        while _rate and now - _rate[0] > 60:
            _rate.popleft()
        if len(_rate) >= RATE_MAX:
            return False
        _rate.append(now)
        return True


def log(**fields):
    """구조화 로그(JSON 한 줄) — 운영에서 파싱 가능."""
    fields["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    sys.stderr.write(json.dumps(fields, ensure_ascii=False) + "\n")
    sys.stderr.flush()


def _jsonable(obj):
    return json.dumps(obj, ensure_ascii=False)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        start = time.time()
        status = 200
        path = urllib.parse.urlparse(self.path).path
        try:
            parsed = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(parsed.query)
            target = q.get("target", [TARGET_BASE])[0]

            # 인증 + 사용자 해석: /api/* 는 토큰 → user_id. 실패 시 401.
            uid = 0
            if path.startswith("/api/"):
                uid = self._resolve_user(q)
                if uid is None:
                    status = 401
                    self._json({"error": "unauthorized — 유효한 API 토큰 필요"}, code=401)
                    return
            # 요청 제한: 스캔류만
            if path in ("/api/scan", "/api/rescan") and not rate_ok():
                status = 429
                self._json({"error": "rate limit — 잠시 후 다시"}, code=429)
                return

            if path in ("/healthz", "/health"):
                mode = "multi" if store.any_users() else ("single" if AUTH_TOKEN else "open")
                self._json({"status": "ok", "target": TARGET_BASE,
                            "target_reachable": _reachable(TARGET_BASE),
                            "auth": mode != "open", "auth_mode": mode,
                            "verifiers": sorted(SCANNERS.keys()),
                            "scanner": {"nuclei_available": scanner.nuclei_available(),
                                        "use_nuclei": os.environ.get("NULLIFY_USE_NUCLEI") == "1"}})
            elif path == "/":
                self._send(PAGE.replace("__TARGET__", TARGET_BASE), "text/html; charset=utf-8")
            elif path == "/api/scan":
                ok, why = authorize(target)                 # ② 권한 게이트
                if not ok:
                    self._json({"authorized": False, "reason": why})
                else:
                    prefer_discover = q.get("discover", ["0"])[0] == "1"
                    with SCAN_LOCK:
                        payload = run_scan(target, prefer_discover)
                    payload["scan_id"] = store.save_scan(payload, uid)   # 이력 저장(사용자별)
                    self._json(payload)
            elif path == "/api/rescan":
                ok, why = authorize(target)
                if not ok:
                    self._json({"authorized": False, "reason": why})
                else:
                    prev_id = store.latest_scan_id_for(target, uid)     # 비교 기준(이전)
                    prev = store.get_scan(prev_id, uid) if prev_id else None
                    prefer_discover = q.get("discover", ["0"])[0] == "1"
                    with SCAN_LOCK:
                        payload = run_scan(target, prefer_discover)
                    payload["scan_id"] = store.save_scan(payload, uid)
                    payload["compare"] = compare_findings(prev["findings"] if prev else [],
                                                          payload["findings"])
                    payload["compare"]["prev_id"] = prev_id
                    if payload["compare"]["new"]:               # 리그레션 → 알림
                        alert = notify.build_alert(target, payload["scan_id"], payload["compare"])
                        payload["alert"] = notify.notify(alert, uid)
                    self._json(payload)
            elif path == "/api/deploy":                            # 데모 헬퍼: 타깃에 패치 배포/원복
                control(target, q.get("kind", [""])[0], q.get("mode", ["safe"])[0])
                self._json({"ok": True, "kind": q.get("kind", [""])[0],
                            "mode": q.get("mode", ["safe"])[0]})
            elif path == "/api/history":
                self._json({"scans": store.list_scans(uid, int(q.get("limit", ["20"])[0]))})
            elif path == "/api/notifications":
                self._json({"notifications": store.list_notifications(uid, int(q.get("limit", ["20"])[0]))})
            elif path == "/api/scan_detail":
                d = store.get_scan(int(q.get("id", ["0"])[0]), uid)
                self._json(d if d else {"error": "not found"}, code=(200 if d else 404))
            elif path == "/api/resolve":
                answer = q.get("answer", ["owner_only"])[0]
                idor_path = q.get("path", ["/order"])[0]
                idor_param = q.get("param", ["id"])[0]
                with SCAN_LOCK:
                    res = resolve_idor(target, answer, idor_path, idor_param)
                self._json(res)
            elif path == "/api/pr":
                with REPO_LOCK:
                    res = github_pr.create_fix(SAMPLE_REPO, q.get("kind", [""])[0])
                self._json(res)
            elif path == "/api/scan_combined":                # 완전체: DAST + SAST 결합
                ok, why = authorize(target)
                if not ok:
                    self._json({"authorized": False, "reason": why})
                else:
                    source = q.get("source", [SAMPLE_REPO])[0]
                    with SCAN_LOCK:
                        dast = run_scan(target)
                    try:
                        with REPO_LOCK:
                            sfind, ssrc = sast.scan(source)
                    except Exception as e:
                        sfind, ssrc = [], "sast 실패: %s" % type(e).__name__
                    res = combine.combine(dast["findings"], sfind)
                    res.update(target=target, source=source, sast_scanner=ssrc)
                    self._json(res)
            elif path == "/api/scan_source":                  # ① SAST: 소스 정적 탐지
                source = q.get("source", [SAMPLE_REPO])[0]
                try:
                    with REPO_LOCK:
                        findings, src = sast.scan(source)
                    self._json({"source": source, "scanner": src, "findings": findings})
                except Exception as e:
                    self._json({"error": str(e)})
            elif path == "/api/connect":
                source = q.get("source", [SAMPLE_REPO])[0]
                kind = q.get("kind", ["sqli"])[0]
                try:
                    with REPO_LOCK:
                        clone = github_pr.connect_repo(source)
                        d = github_pr.create_fix(clone, kind)
                    d["cloned_from"], d["clone_path"] = source, clone
                except Exception as e:
                    d = {"error": str(e)}
                self._json(d)
            else:
                status = 404
                self._json({"error": "not found"}, code=404)
        except Exception:
            status = 500
            traceback.print_exc()                           # 서버측만 — 세부는 클라에 안 흘림
            try:
                self._json({"error": "internal server error"}, code=500)
            except Exception:
                pass
        finally:
            log(method="GET", path=path, status=status, ms=int((time.time() - start) * 1000))

    def _resolve_user(self, q):
        """토큰 → user_id. 반환 None = 미인증(401). 0 = 개발/단일 모드."""
        tok = self.headers.get("X-API-Token") or q.get("token", [""])[0]
        if store.any_users():                               # 멀티유저 모드
            u = store.user_for_token(tok)
            return u["id"] if u else None
        if AUTH_TOKEN:                                       # 단일 토큰 모드
            return 0 if tok == AUTH_TOKEN else None
        return 0                                             # 개발 모드(열림)

    def do_POST(self):                                      # 이 API 는 GET 전용
        self._json({"error": "method not allowed"}, code=405)

    def _json(self, obj, code=200):
        self._send(json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8", code)

    def _send(self, text, ctype, code=200):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass                                                # 기본 로그 끔(우리 구조화 로그 사용)


if __name__ == "__main__":
    host = os.environ.get("NULLIFY_HOST", "127.0.0.1")
    port = int(os.environ.get("NULLIFY_PORT", "8000"))
    srv = http.server.ThreadingHTTPServer((host, port), Handler)   # 동시성
    srv.daemon_threads = True
    log(event="startup", host=host, port=port, target=TARGET_BASE,
        auth=bool(AUTH_TOKEN), rate_max=RATE_MAX)
    if not AUTH_TOKEN:
        log(level="warn", msg="NULLIFY_API_TOKEN 미설정 — API 가 무방비(개발 모드). 배포 시 반드시 설정.")
    print("Nullify: http://%s:%d  (Ctrl+C 종료) · /healthz · 인증:%s" % (
        host, port, "ON" if AUTH_TOKEN else "OFF(개발)"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
        log(event="shutdown")