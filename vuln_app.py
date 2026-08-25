"""
Nullify 데모용 '일부러 취약한' 타깃 앱.

- 실제 서비스가 아니라, 우리 검증기가 안전하게 찔러볼 '연습용 과녁'이다.
- 남의 사이트를 절대 건드리지 않으려고, 우리가 직접 로컬(127.0.0.1)에만 띄운다.
- 설치 없이 돌도록 표준 라이브러리만 사용:
    http.server  = 파이썬 기본 웹서버
    sqlite3      = 파이썬에 내장된 초경량 DB
    socketserver = 요청을 스레드로 동시에 처리하게 해주는 것

엔드포인트 2개로 '취약 vs 안전'을 나란히 둔다 → 검증기가 둘을 구분하는지 본다.

2026-08-25: do_POST 추가. do_GET 의 라우팅을 _dispatch 로 분리해 GET/POST 가
같은 라우팅을 공유하게 함(로직 변경 없음, 파라미터 출처만 쿼리→바디로 달라짐).
검증기 POST 확장을 위한 과녁.
"""
import os
import html
import sqlite3
import tempfile
import subprocess
import http.server
import socketserver
import threading
import urllib.parse
import urllib.request


def build_db():
    # :memory: = 디스크가 아니라 메모리에만 존재하는 DB. 실행 끝나면 사라진다.
    # check_same_thread=False : 여러 스레드(요청)가 같은 연결을 쓰게 허용.
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.execute("CREATE TABLE users(id TEXT, name TEXT, secret TEXT)")
    con.executemany(
        "INSERT INTO users VALUES(?,?,?)",
        [("1", "alice", "alice-secret"),
         ("2", "bob",   "bob-secret"),
         ("3", "carol", "carol-secret")],
    )
    con.commit()
    return con


DB = build_db()
LOCK = threading.Lock()   # 하나의 DB 연결을 여러 요청이 공유하므로 한 번에 하나씩만


def query_vuln(id_value):
    # ★취약: 사용자 입력을 문자열로 '그대로 이어붙임' → 입력이 SQL 구문으로 섞인다.
    #   id_value 가 "1' AND '1'='1" 이면 실제 실행되는 SQL 은
    #   SELECT id,name FROM users WHERE id='1' AND '1'='1'  이 되어버린다.
    sql = "SELECT id,name FROM users WHERE id='" + id_value + "'"
    with LOCK:
        return DB.execute(sql).fetchall()


def query_safe(id_value):
    # 안전: '?' 파라미터 바인딩. 입력은 '값'으로만 취급되어 SQL 로 해석되지 않는다.
    sql = "SELECT id,name FROM users WHERE id=?"
    with LOCK:
        return DB.execute(sql, (id_value,)).fetchall()


# /user 라우트가 실제로 호출하는 구현. 닫힌 루프 데모에서 이걸 안전판으로 '교체'한다.
# (실제 제품에선 이 교체가 곧 'PR 병합 후 재배포'에 해당한다.)
USER_IMPL = query_vuln


def set_user_impl(fn):
    global USER_IMPL
    USER_IMPL = fn


def search_vuln(q):
    # ★취약: 사용자 입력을 이스케이프 없이 HTML 에 그대로 삽입 → 반사형 XSS.
    #   q 가 "<img src=x onerror=alert(1)>" 이면 그 태그가 브라우저에서 실행된다.
    return "<p>results for: " + q + "</p>"


def search_safe(q):
    # 안전: html.escape 로 <, >, & 를 무력화 → 태그가 '글자'로만 보인다.
    return "<p>results for: " + html.escape(q) + "</p>"


SEARCH_IMPL = search_vuln


def set_search_impl(fn):
    global SEARCH_IMPL
    SEARCH_IMPL = fn


# --- 주문 조회 (IDOR / 접근제어) ---
ORDERS = {"1001": ("alice", "노트북 1대, 카드결제"),
          "1002": ("bob",   "키보드 1개, 계좌이체")}
TOKENS = {"sess_alice": "alice", "sess_bob": "bob"}   # 토큰 → 로그인 사용자


def order_vuln(order_id, token):
    # ★취약(IDOR): 토큰이 '유효하기만' 하면 소유자 검사 없이 아무 주문이나 내준다.
    if token not in TOKENS:
        return "401 unauthorized"
    owner, content = ORDERS.get(order_id, (None, None))
    if owner is None:
        return "404 not found"
    return "order %s (owner=%s): %s" % (order_id, owner, content)


def order_safe(order_id, token):
    # 안전: '요청자 == 주문 소유자' 일 때만 내준다.
    user = TOKENS.get(token)
    if user is None:
        return "401 unauthorized"
    owner, content = ORDERS.get(order_id, (None, None))
    if owner is None:
        return "404 not found"
    if owner != user:
        return "403 forbidden"
    return "order %s (owner=%s): %s" % (order_id, owner, content)


ORDER_IMPL = order_vuln


def set_order_impl(fn):
    global ORDER_IMPL
    ORDER_IMPL = fn


# --- 파일 다운로드 (Path Traversal / LFI) ---
_ROOT = tempfile.mkdtemp(prefix="nullify_")
WEBROOT = os.path.join(_ROOT, "public")
os.makedirs(WEBROOT, exist_ok=True)
with open(os.path.join(WEBROOT, "readme.txt"), "w", encoding="utf-8") as _f:
    _f.write("공개 파일입니다.")
with open(os.path.join(_ROOT, "secret.txt"), "w", encoding="utf-8") as _f:
    _f.write("DB_PASSWORD=nullify-super-secret")   # 웹루트 '밖'의 민감 파일


def download_vuln(name):
    # ★취약: 사용자 경로를 검사 없이 그대로 합쳐 연다 → "../" 로 웹루트 상위 탈출.
    try:
        with open(os.path.join(WEBROOT, name), "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return "404 not found"


def download_safe(name):
    # 안전: 최종 실경로가 WEBROOT 안인지 검사. 벗어나면 거부.
    full = os.path.realpath(os.path.join(WEBROOT, name))
    root = os.path.realpath(WEBROOT)
    if not (full == root or full.startswith(root + os.sep)):
        return "403 forbidden"
    try:
        with open(full, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return "404 not found"


DOWNLOAD_IMPL = download_vuln


def set_download_impl(fn):
    global DOWNLOAD_IMPL
    DOWNLOAD_IMPL = fn


# --- 명령어 주입 (A03) ---
def ping_vuln(host):
    # ★취약: 입력을 셸 명령 문자열에 그대로 이어붙임 → 명령어 주입.
    r = subprocess.run("echo pong " + host, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def ping_safe(host):
    # 안전: 셸 메타문자가 있으면 거부(명령 분리 자체를 막음).
    if any(c in host for c in ";&|`$<>\n\r"):
        return "rejected: illegal characters"
    r = subprocess.run("echo pong " + host, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


CMD_IMPL = ping_vuln


def set_cmd_impl(fn):
    global CMD_IMPL
    CMD_IMPL = fn


# --- 오픈 리다이렉트 (A01) ---
def redirect_target_vuln(nxt):
    return nxt or "/"                       # ★취약: 외부 URL 도 그대로 리다이렉트


def redirect_target_safe(nxt):
    # 안전: 상대경로/같은 사이트만 허용, 그 외는 홈으로.
    if nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return "/"


REDIR_IMPL = redirect_target_vuln


def set_redir_impl(fn):
    global REDIR_IMPL
    REDIR_IMPL = fn


# --- SSRF (A10) ---
INTERNAL_MARKER = "INTERNAL_ONLY_SECRET_9f2a"


def fetch_url_vuln(url):
    # ★취약: 사용자가 준 URL 을 서버가 그대로 가져온다 → 내부망 접근 가능.
    try:
        return urllib.request.urlopen(url, timeout=3).read().decode("utf-8", "replace")
    except Exception as e:
        return "error: %s" % e


def fetch_url_safe(url):
    # 안전: 내부/사설 대상 차단.
    low = url.lower()
    if any(k in low for k in ("127.0.0.1", "localhost", "169.254", "internal", "0.0.0.0")):
        return "blocked: internal target"
    try:
        return urllib.request.urlopen(url, timeout=3).read().decode("utf-8", "replace")
    except Exception as e:
        return "error: %s" % e


FETCH_IMPL = fetch_url_vuln


def set_fetch_impl(fn):
    global FETCH_IMPL
    FETCH_IMPL = fn


# --- 보안 헤더 (A05) ---
HEADER_MODE = "vuln"     # vuln = 보안 헤더 없음, safe = 있음


def set_header_mode(mode):
    global HEADER_MODE
    HEADER_MODE = mode


# --- 노출된 시크릿 (A02) ---
def config_vuln():
    # ★취약: API 키를 프론트 코드에 그대로 박음.
    return 'var API_KEY="AKIA' + 'EXAMPLE1234567890";\nfetch("/api");'


def config_safe():
    return 'var API_KEY=window.__CFG.key;\nfetch("/api");'   # 키는 서버가 주입


CONFIG_IMPL = config_vuln


def set_config_impl(fn):
    global CONFIG_IMPL
    CONFIG_IMPL = fn


# --- 오래된 컴포넌트 (A06) ---
def assets_vuln():
    return "<!-- lib: jquery-1.4.2 -->"     # 알려진 취약 버전


def assets_safe():
    return "<!-- lib: jquery-3.7.1 -->"


ASSET_IMPL = assets_vuln


def set_asset_impl(fn):
    global ASSET_IMPL
    ASSET_IMPL = fn


# --- 제어 엔드포인트: '패치 배포(safe) / 원복(vuln)' 을 런타임에 반영 (데모/개발 전용) ---
# 엔진(web.py)이 이 앱을 import 하지 않고 HTTP 로만 제어하게 해준다.
# 실제로는 'PR 병합 → CI 재배포' 에 해당하는 자리(데모에선 이 스위치로 대신).
CONTROLS = {
    "sqli":      (set_user_impl,     query_vuln,             query_safe),
    "xss":       (set_search_impl,   search_vuln,            search_safe),
    "traversal": (set_download_impl, download_vuln,          download_safe),
    "cmdi":      (set_cmd_impl,      ping_vuln,              ping_safe),
    "redirect":  (set_redir_impl,    redirect_target_vuln,   redirect_target_safe),
    "ssrf":      (set_fetch_impl,    fetch_url_vuln,         fetch_url_safe),
    "idor":      (set_order_impl,    order_vuln,             order_safe),
    "secret":    (set_config_impl,   config_vuln,            config_safe),
    "component": (set_asset_impl,    assets_vuln,            assets_safe),
}


def apply_control(vuln, mode):
    if vuln == "headers":
        set_header_mode(mode)
        return True
    if vuln in CONTROLS:
        setter, vfn, sfn = CONTROLS[vuln]
        setter(sfn if mode == "safe" else vfn)
        return True
    return False


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # 파라미터를 쿼리스트링에서 뽑아 공용 라우팅(_dispatch)에 넘긴다.
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        self._dispatch(parsed, params)

    def do_POST(self):
        # do_GET 과 같은 라우팅을 타되, 파라미터를 쿼리스트링이 아니라
        # POST 바디(form-urlencoded)에서 뽑는다. 검증기가 POST 로 찔러볼 과녁.
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        params = urllib.parse.parse_qs(raw, keep_blank_values=True)
        # 쿼리스트링이 함께 오면 병합(바디에 없는 키만 보충).
        for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
            params.setdefault(k, v)
        self._dispatch(parsed, params)

    def _dispatch(self, parsed, params):
        # --- 제어 라우트 (데모/개발 전용): 패치 배포/원복 ---
        if parsed.path == "/control":
            ok = apply_control(params.get("vuln", [""])[0], params.get("mode", ["vuln"])[0])
            self._send(200, "ok" if ok else "unknown")
            return

        # --- 반사형 XSS 라우트 (입력을 HTML 로 되돌려줌) ---
        if parsed.path in ("/search", "/search_safe"):
            q = params.get("q", [""])[0]
            impl = SEARCH_IMPL if parsed.path == "/search" else search_safe
            self._send(200, "<html><body>%s</body></html>" % impl(q),
                       ctype="text/html; charset=utf-8")
            return

        # --- Path Traversal 라우트 ---
        if parsed.path == "/download":
            name = params.get("file", [""])[0]
            self._send(200, DOWNLOAD_IMPL(name))
            return

        # --- 명령어 주입 라우트 ---
        if parsed.path == "/ping":
            self._send(200, CMD_IMPL(params.get("host", [""])[0]))
            return

        # --- 오픈 리다이렉트 라우트 ---
        if parsed.path == "/go":
            target = REDIR_IMPL(params.get("next", [""])[0])
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # --- SSRF 라우트 ---
        if parsed.path == "/fetch":
            self._send(200, FETCH_IMPL(params.get("url", [""])[0]))
            return
        if parsed.path == "/internal":            # 내부 전용(원래 밖에서 못 봐야 함)
            self._send(200, INTERNAL_MARKER)
            return

        # --- 보안 헤더 라우트 ---
        if parsed.path == "/app":
            extra = {}
            if HEADER_MODE == "safe":
                extra = {"X-Frame-Options": "DENY",
                         "Content-Security-Policy": "default-src 'self'"}
            self._send(200, "<html>app</html>", "text/html; charset=utf-8", extra)
            return

        # --- 노출된 시크릿 라우트 ---
        if parsed.path == "/config.js":
            self._send(200, CONFIG_IMPL(), "application/javascript; charset=utf-8")
            return

        # --- 오래된 컴포넌트 라우트 ---
        if parsed.path == "/assets":
            self._send(200, ASSET_IMPL(), "text/html; charset=utf-8")
            return

        # --- IDOR / 접근제어 라우트 ---
        if parsed.path == "/order":
            oid = params.get("id", [""])[0]
            tok = params.get("token", [""])[0]
            self._send(200, ORDER_IMPL(oid, tok))
            return

        # --- SQL 인젝션 라우트 ---
        id_value = params.get("id", [""])[0]
        try:
            if parsed.path == "/user":
                rows = USER_IMPL(id_value)   # 현재 배포된 구현(패치 전=취약 / 패치 후=안전)
            elif parsed.path == "/user_safe":
                rows = query_safe(id_value)
            else:
                self.send_error(404, "not found")
                return
        except Exception as e:
            # SQL 오류를 그대로 노출 — 실제 취약 앱에서 흔한 상황이자
            # '에러 기반' 인젝션의 근거가 되기도 한다.
            self._send(500, "SQL error: %s" % e)
            return
        text = "rows:\n" + "\n".join("%s,%s" % (r[0], r[1]) for r in rows)
        self._send(200, text)

    def _send(self, code, text, ctype="text/plain; charset=utf-8", extra=None):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # 콘솔을 조용히 (요청 로그 끔)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def serve_in_thread(port=8009):
    """서버를 백그라운드 스레드로 띄우고 srv 객체를 돌려준다(데모용)."""
    srv = Server(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    srv = Server(("127.0.0.1", 8009), Handler)
    print("취약 타깃 앱 실행: http://127.0.0.1:8009  (Ctrl+C 로 종료)")
    print("  예) http://127.0.0.1:8009/user?id=1")
    srv.serve_forever()