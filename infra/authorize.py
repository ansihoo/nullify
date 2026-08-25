"""
② 권한 게이트 — '겨눠도 되는 대상인가'를 강제한다.

배포 가능한 보안 도구의 법적 필수 요소:
  허가 없이 남의 서버를 스캔/공격하면 정보통신망법 위반이다.
  그래서 스캔 '전에' 대상이 허용 범위인지 반드시 확인하고, 아니면 거부한다.

정책(단순화):
  - 로컬/사설망(127.x, 10.x, 192.168.x, localhost) → 자동 허용 (내 환경)
  - 운영자 승인 목록(ALLOWLIST)에 있는 공개 도메인 → 허용
  - 그 외 공개 대상 → 거부. 실제 배포에선 '소유권 증명'(DNS TXT 챌린지 등)을 요구해야 한다.
    (동의 체크박스만으론 부족 — 남의 것을 '내 것'이라 거짓 체크할 수 있으니까)
"""
import os
import ipaddress
import urllib.parse

# 운영자가 소유/스코프를 확인한 공개 대상. 예: {"staging.myapp.com"}
# 코드 수정 없이 자기 소유 도메인만 열도록 환경변수로도 받는다(콤마 구분).
#   예)  NULLIFY_ALLOWLIST=case-intake-pro.lovable.app,staging.myapp.com
# ※ 반드시 '본인이 소유/스코프를 가진' 대상만. 남의 사이트를 넣으면 불법 스캔이 된다.
# 기본 승인 목록 — 소유자가 확인한 대상(예: 내가 만든 테스트 사이트).
_DEFAULT_ALLOW = {
    "case-intake-pro.lovable.app",   # 소유자 본인 소유 테스트 사이트
    "case-intake-pro-vuln-target.vercel.app",   # 팀원이 만든 데모용 취약 과녁
}
ALLOWLIST = _DEFAULT_ALLOW | set(
    h.strip().lower()
    for h in os.environ.get("NULLIFY_ALLOWLIST", "").split(",")
    if h.strip()
)


def _host(target):
    return (urllib.parse.urlparse(target).hostname or "").lower()


def _is_private(host):
    if host in ("localhost", ""):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False   # IP 가 아니라 도메인명 → 사설로 취급하지 않음


def authorize(target):
    """(허용?, 사유) 반환."""
    host = _host(target)
    if _is_private(host):
        return True, "로컬/사설 대상 — 허용"
    if host in ALLOWLIST:
        return True, "운영자 승인 대상 — 허용"
    return False, ("허가되지 않은 대상: %s — 소유권 증명(DNS TXT 등) 또는 "
                   "ALLOWLIST 등록이 필요합니다." % host)


if __name__ == "__main__":
    for t in ["http://127.0.0.1:8009/x", "http://192.168.0.5/", "https://example.com/"]:
        print(t, "→", authorize(t))
