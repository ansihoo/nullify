"""
오래된 컴포넌트(Vulnerable/Outdated Components, A06) 검증기 — 수동 결정론.

응답에서 라이브러리 버전을 뽑아 '알려진 취약 버전 기준'과 대조한다.
여기선 jquery 3.0 미만을 취약으로 본다. (오라클 = 버전 비교, 결정론)
실전에선 이 기준표가 CVE/취약 버전 DB 가 된다.
"""
import re
import urllib.request
import urllib.error

# 라이브러리 -> '이 (major) 미만이면 취약' 기준. (데모용 단순화)
MIN_SAFE_MAJOR = {"jquery": 3}
VER_RE = re.compile(r"(jquery)-(\d+)\.(\d+)\.(\d+)")


def _body(url):
    try:
        return urllib.request.urlopen(url, timeout=5).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace")


def verify(base_url):
    m = VER_RE.search(_body(base_url))
    if not m:
        return "FALSE_POSITIVE", "알려진 취약 라이브러리 버전 없음", {}
    lib, major = m.group(1), int(m.group(2))
    ver = "%s-%s.%s.%s" % (lib, m.group(2), m.group(3), m.group(4))
    if major < MIN_SAFE_MAJOR.get(lib, 0):
        return "CONFIRMED", "%s 는 알려진 취약 버전(%d.x 미만 권고)" % (ver, MIN_SAFE_MAJOR[lib]), {"version": ver}
    return "FALSE_POSITIVE", "%s 는 최신 계열" % ver, {"version": ver}


if __name__ == "__main__":
    from vuln_app import serve_in_thread
    srv = serve_in_thread(8026)
    print("/assets", verify("http://127.0.0.1:8026/assets"))
    srv.shutdown()
