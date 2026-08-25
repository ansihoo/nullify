"""
CI 보안 게이트 — CI 파이프라인에서 Nullify 엔진을 호출해 취약점을 검사하고,
임계 이상이 있으면 종료코드 1 로 빌드를 '실패'시킨다.

CI 에서의 진짜 값(정직하게):
  - 탐지 게이트: 이 배포에 진짜 터지는 취약점이 있으면 막는다.
  - 리그레션 추적: rescan 모드로 '이전 배포 대비 새로 생긴 것'을 잡는다.
  (수정 후 재검증/영수증은 /control 이 있는 데모 타깃 전용 — 실 앱엔 없음.)

환경변수:
  NULLIFY_ENGINE     엔진 주소 (기본 http://127.0.0.1:8000)
  NULLIFY_API_TOKEN  엔진 인증 토큰(멀티/단일 모드일 때)
  NULLIFY_TARGET     검사 대상 URL (또는 첫 번째 인자)
  NULLIFY_MODE       scan | rescan (기본 rescan = 추세 비교)
  NULLIFY_FAIL_ON    critical | question | warn | none (기본 critical)

종료코드: 0=통과, 1=게이트 실패(취약), 2=오류/거부
"""
import os
import sys
import json
import urllib.parse
import urllib.request

ENGINE = os.environ.get("NULLIFY_ENGINE", "http://127.0.0.1:8000")
TOKEN = os.environ.get("NULLIFY_API_TOKEN", "")
FAIL_ON = os.environ.get("NULLIFY_FAIL_ON", "critical")
ORDER = ["critical", "question", "warn"]


def _get(path):
    req = urllib.request.Request(ENGINE + path,
                                 headers={"X-API-Token": TOKEN} if TOKEN else {})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read().decode("utf-8"))


def _gha_summary(text):
    """GitHub Actions 스텝 요약에 기록(있을 때만)."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError:
            pass


def main():
    target = os.environ.get("NULLIFY_TARGET") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not target:
        print("사용법: NULLIFY_TARGET=<url> python nullify_ci.py")
        return 2
    mode = os.environ.get("NULLIFY_MODE", "rescan")
    try:
        d = _get("/api/%s?target=%s" % (mode, urllib.parse.quote(target, safe="")))
    except Exception as e:
        print("엔진 호출 실패:", e)
        return 2
    if d.get("authorized") is False:
        print("스캔 거부:", d.get("reason"))
        return 2

    line = "대상 %s | 진짜 %d · 질문 %d · 경고 %d" % (target, d["crit"], d["ques"], d["warn"])
    print(line)
    _gha_summary("### Nullify 보안 게이트\n- " + line)
    if "compare" in d:
        C = d["compare"]
        print("  재검증: 고쳐짐 %d · 새로생김 %d · 그대로 %d" %
              (len(C["fixed"]), len(C["new"]), len(C["unchanged"])))
        if C["new"]:
            print("  ::error::리그레션(새로 생김): " + ", ".join(C["new"]))
            _gha_summary("- ⚠ 리그레션: " + ", ".join(C["new"]))

    if FAIL_ON in ORDER:
        counts = {"critical": d["crit"], "question": d["ques"], "warn": d["warn"]}
        bad = sum(counts[s] for s in ORDER[:ORDER.index(FAIL_ON) + 1])
        if bad > 0:
            print("::error::보안 게이트 실패 — '%s 이상' %d건" % (FAIL_ON, bad))
            _gha_summary("- ❌ **게이트 실패**: %s 이상 %d건" % (FAIL_ON, bad))
            return 1
    print("보안 게이트 통과")
    _gha_summary("- ✅ 게이트 통과")
    return 0


if __name__ == "__main__":
    sys.exit(main())
