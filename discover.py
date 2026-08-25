"""
① 후보 자동발견(Discovery) — 외부 스캐너 없이도 '임의 앱'에서 검증 후보를 찾아낸다.

왜 필요?
  scanner.py 는 Nuclei 리포트(또는 샘플 JSONL)에 의존한다. Nuclei 가 설치돼 있지 않고
  대상이 우리 데모 토이 앱이 아니면, 샘플의 토이 경로(/user, /search...)는 실제 앱에
  존재하지 않아 '찔러볼 곳'이 하나도 없다. 이 모듈은 대상 앱을 직접 훑어서
  "어디를(경로) 무슨 파라미터로 찔러볼지" 목록을 만든다.

두 전략을 함께 쓴다 (실제 DAST 스캐너와 동일한 구성):
  (A) 크롤(crawl): 시작 페이지에서 <a href>, <form>, <script src> 를 따라가며
      링크·폼·쿼리 파라미터를 수집한다. 같은 출처(same-origin)만, 페이지 수·깊이 제한.
      → 링크로 연결된 '정상' 앱에서 잘 먹는다.
  (B) 탐침(probe): 크롤로는 안 걸리는 '링크 없는' 엔드포인트를 위해,
      흔한 경로+파라미터 소사전으로 직접 찔러 404 가 아닌 것만 후보로 채택한다.
      → 인덱스 페이지가 없는 API 형태 앱(우리 토이 앱 포함)에서 필요.

핵심 원칙:
  여기서 만든 후보는 전부 '가설'이다. 진짜 취약한지는 뒤의 검증기(③)가 실제로 찔러 판정한다.
  검증기가 결정론이라 헛후보는 그냥 FALSE_POSITIVE 로 걸러지므로, 발견은 넉넉히 해도 안전하다.
  (= 발견은 재현율/recall 을 챙기고, 정밀도/precision 은 검증기가 책임진다.)

stdlib 만 사용: urllib(요청/URL), html.parser(HTML 파싱). BeautifulSoup 같은 외부 의존 없음.
"""
import urllib.request
import urllib.parse
from html.parser import HTMLParser


# ── 파라미터 이름 → 어떤 검증기(kind)로 찔러볼지 추정 ───────────────────────
# 한 파라미터가 여러 kind 로 매핑될 수 있다(예: url 은 redirect 도 ssrf 도 의심).
# 검증기가 결정론이라 틀린 추정은 알아서 FALSE_POSITIVE 로 떨어진다.
PARAM_KINDS = [
    (("id", "uid", "userid", "pid", "no", "num", "seq"), ["sqli"]),
    (("q", "query", "search", "keyword", "kw", "term", "s", "name",
      "comment", "msg", "message", "text", "content", "title"), ["xss"]),
    (("file", "filename", "path", "filepath", "page", "template",
      "include", "doc", "dir", "download", "read"), ["traversal"]),
    (("url", "uri", "link", "next", "redirect", "return", "returnurl",
      "dest", "destination", "target", "continue", "goto", "u", "to"), ["redirect", "ssrf"]),
    (("host", "ip", "cmd", "command", "exec", "domain", "addr", "ping"), ["cmdi"]),
]

# 파라미터 이름을 못 알아볼 때의 기본 추정(가장 흔한 주입 2종만 — 과도한 탐침 방지).
DEFAULT_KINDS = ["sqli", "xss"]

# 경로 이름이 이거면 IDOR(교차열람) 후보도 함께 — scan_idor 는 경로/파라미터를 무시하고
# 고정 시나리오(bob 가 alice 주문 열람)를 돌리므로, 주문/계정류 경로에서만 켠다.
IDOR_PATH_HINTS = ("order", "account", "profile", "invoice", "cart", "message", "doc")

# ── (B) 탐침용 소사전: 흔한 '경로 + 파라미터' 조합 ──────────────────────────
# 링크가 없어 크롤로 안 걸리는 엔드포인트를 직접 찔러본다. 404 아니면 후보 채택.
PROBE_PARAM_ENDPOINTS = [
    ("/user", "id"), ("/users", "id"), ("/account", "id"), ("/profile", "id"),
    ("/order", "id"), ("/item", "id"), ("/product", "id"), ("/view", "id"),
    ("/search", "q"), ("/find", "q"), ("/query", "q"),
    ("/download", "file"), ("/file", "path"), ("/read", "file"), ("/page", "file"),
    ("/ping", "host"), ("/exec", "cmd"), ("/run", "cmd"),
    ("/go", "next"), ("/redirect", "url"), ("/out", "url"),
    ("/fetch", "url"), ("/proxy", "url"), ("/api/fetch", "url"),
]
# 파라미터 없이 페이지 자체를 보는 검증(헤더/시크릿/컴포넌트)용 경로.
PROBE_PAGE_ENDPOINTS = [
    ("/", "headers"), ("/app", "headers"), ("/index.html", "headers"),
    ("/config.js", "secret"), ("/config", "secret"), ("/settings.js", "secret"),
    ("/assets", "component"), ("/static", "component"), ("/vendor", "component"),
]


def _kinds_for_param(name):
    n = name.lower()
    for keys, kinds in PARAM_KINDS:
        if n in keys:
            return list(kinds)
    return list(DEFAULT_KINDS)


class _LinkParser(HTMLParser):
    """<a href>, <form action>+<input name>, <script src> 만 뽑는 최소 파서."""
    def __init__(self):
        super().__init__()
        self.links = []          # href 문자열들
        self.scripts = []        # script src 들
        self.forms = []          # (action, [input names])
        self._cur_form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "form":
            self._cur_form = [a.get("action", ""), []]
        elif tag in ("input", "textarea", "select") and self._cur_form is not None:
            if a.get("name"):
                self._cur_form[1].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._cur_form is not None:
            self.forms.append(tuple(self._cur_form))
            self._cur_form = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """3xx 를 따라가지 않는다. 오픈 리다이렉트(/go 같은) 엔드포인트는 302 자체가
    '살아있는 후보'인데, 자동 추적하면 최종 목적지(대개 404)로 흘러가 놓친다."""
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _fetch(url, timeout=5):
    """(status, content_type, body) 반환. 실패하면 (None, '', '').
    리다이렉트는 따라가지 않는다(3xx 도 유효한 엔드포인트로 취급)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Nullify-Discover/1.0"})
        with _OPENER.open(req, timeout=timeout) as r:
            ctype = r.headers.get("Content-Type", "")
            body = r.read(200_000).decode("utf-8", "replace")  # 200KB 상한
            return r.status, ctype, body
    except urllib.error.HTTPError as e:
        # 3xx(리다이렉트 미추적 시 여기로) 는 살아있는 엔드포인트 → status 로 반환.
        # 404 등도 status 로 구분 가능.
        return e.code, e.headers.get("Content-Type", "") if e.headers else "", ""
    except Exception:
        return None, "", ""


def _same_origin(base, url):
    b, u = urllib.parse.urlparse(base), urllib.parse.urlparse(url)
    return (u.scheme, u.netloc) == (b.scheme, b.netloc)


def _add_param_candidate(seen, out, path, param, scanner_label):
    """(path, param, kind) 중복 제거하며 후보 추가."""
    for kind in _kinds_for_param(param):
        key = (kind, path, param)
        if key in seen:
            continue
        seen.add(key)
        out.append({"kind": kind, "path": path, "param": param, "scanner": scanner_label})
    # 주문/계정류 경로면 IDOR 도 한 번(경로 기준, 파라미터 무관).
    if any(h in path.lower() for h in IDOR_PATH_HINTS):
        key = ("idor", path, "")
        if key not in seen:
            seen.add(key)
            out.append({"kind": "idor", "path": path, "param": param, "scanner": scanner_label})


def crawl(base, max_pages=25, max_depth=2, timeout=5):
    """(A) same-origin BFS 크롤 → 후보 리스트. 링크·폼·쿼리파라미터·스크립트 수집."""
    base = base.rstrip("/")
    seen_cand, out = set(), []
    visited, queue = set(), [(base + "/", 0)]

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        norm = url.split("#")[0]
        if norm in visited:
            continue
        visited.add(norm)

        status, ctype, body = _fetch(norm, timeout)
        if status is None:
            continue

        # 이 페이지 자체는 헤더 검증 후보(HTML 응답이면).
        pu = urllib.parse.urlparse(norm)
        if "html" in ctype.lower():
            k = ("headers", pu.path, "")
            if k not in seen_cand:
                seen_cand.add(k)
                out.append({"kind": "headers", "path": pu.path or "/", "param": "",
                            "scanner": "discover(crawl)"})

        # 이 URL 에 이미 쿼리 파라미터가 붙어 있으면 그것도 후보.
        for p in urllib.parse.parse_qs(pu.query):
            _add_param_candidate(seen_cand, out, pu.path or "/", p, "discover(crawl)")

        if "html" not in ctype.lower():
            continue

        parser = _LinkParser()
        try:
            parser.feed(body)
        except Exception:
            pass

        # 링크: 같은 출처만 큐에 넣고, 쿼리 파라미터는 후보로.
        for href in parser.links:
            full = urllib.parse.urljoin(norm, href)
            if not _same_origin(base, full):
                continue
            hu = urllib.parse.urlparse(full)
            for p in urllib.parse.parse_qs(hu.query):
                _add_param_candidate(seen_cand, out, hu.path or "/", p, "discover(crawl)")
            if depth < max_depth and full.split("#")[0] not in visited:
                queue.append((full, depth + 1))

        # 폼: action 경로 + 각 input name 을 파라미터 후보로.
        for action, names in parser.forms:
            full = urllib.parse.urljoin(norm, action or norm)
            if not _same_origin(base, full):
                continue
            apath = urllib.parse.urlparse(full).path or "/"
            for name in names:
                _add_param_candidate(seen_cand, out, apath, name, "discover(form)")

        # 스크립트: .js 는 시크릿·컴포넌트 검증 후보.
        for src in parser.scripts:
            full = urllib.parse.urljoin(norm, src)
            if not _same_origin(base, full):
                continue
            spath = urllib.parse.urlparse(full).path or "/"
            for kind in ("secret", "component"):
                k = (kind, spath, "")
                if k not in seen_cand:
                    seen_cand.add(k)
                    out.append({"kind": kind, "path": spath, "param": "",
                                "scanner": "discover(crawl)"})
    return out


def probe(base, timeout=4):
    """(B) 흔한 경로+파라미터 소사전 탐침 → 404 아닌 것만 후보. 링크 없는 앱용."""
    base = base.rstrip("/")
    seen_cand, out = set(), []

    for path, param in PROBE_PARAM_ENDPOINTS:
        status, _, _ = _fetch(base + path + "?" + param + "=1", timeout)
        if status is not None and status != 404:
            _add_param_candidate(seen_cand, out, path, param, "discover(probe)")

    for path, kind in PROBE_PAGE_ENDPOINTS:
        status, ctype, _ = _fetch(base + path, timeout)
        if status is None or status == 404:
            continue
        # headers 는 HTML 응답에만 의미. secret/component 는 그대로.
        if kind == "headers" and "html" not in ctype.lower():
            continue
        k = (kind, path, "")
        if k not in seen_cand:
            seen_cand.add(k)
            out.append({"kind": kind, "path": path, "param": "", "scanner": "discover(probe)"})
    return out


def discover(base, max_pages=25, max_depth=2, timeout=5):
    """크롤 + 탐침을 합쳐 (kind, path, param) 중복 제거한 후보 리스트를 돌려준다.
    깊이·페이지 수는 환경변수로도 조정 가능(코드 수정 없이 튜닝):
      NULLIFY_CRAWL_DEPTH, NULLIFY_CRAWL_PAGES."""
    import os
    max_depth = int(os.environ.get("NULLIFY_CRAWL_DEPTH", max_depth))
    max_pages = int(os.environ.get("NULLIFY_CRAWL_PAGES", max_pages))
    merged, seen = [], set()
    for c in crawl(base, max_pages, max_depth, timeout) + probe(base, timeout):
        key = (c["kind"], c["path"], c["param"])
        if key in seen:
            continue
        seen.add(key)
        merged.append(c)
    return merged


if __name__ == "__main__":
    import sys
    tgt = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8009"
    cands = discover(tgt)
    print("대상:", tgt, "| 발견 후보:", len(cands))
    for c in sorted(cands, key=lambda x: (x["path"], x["kind"])):
        print("  %-10s %-16s param=%-8s [%s]" % (c["kind"], c["path"], c["param"], c["scanner"]))
