"""
수정 카탈로그 — 취약점 종류별 '코드 패치(before → after)'.

이건 '사용자 레포의 파일에 적용될 실제 수정'을 나타낸다.
github_pr.py 가 이 카탈로그로 진짜 git 브랜치/커밋을 만든다.
(런타임 스캐너는 코드를 모른다 — 코드 수정은 '레포 쪽'의 일이라 여기 분리해 둔다.)

주의: app.py 는 아래 before 블록들을 그대로 이어붙여 만든다 →
      before 가 파일의 정확한 부분문자열이 되도록 보장(패치가 확실히 적용됨).
"""

FIXES = {
    "sqli": {
        "file": "app.py", "branch": "nullify/fix-sqli",
        "title": "fix(security): SQL Injection in get_user",
        "before": ('def get_user(id_value, db):\n'
                   '    sql = "SELECT id, name FROM users WHERE id=\'" + id_value + "\'"\n'
                   '    return db.execute(sql).fetchall()\n'),
        "after":  ('def get_user(id_value, db):\n'
                   '    sql = "SELECT id, name FROM users WHERE id=?"\n'
                   '    return db.execute(sql, (id_value,)).fetchall()\n'),
    },
    "xss": {
        "file": "app.py", "branch": "nullify/fix-xss",
        "title": "fix(security): Reflected XSS in render_search",
        "before": ('def render_search(q):\n'
                   '    return "<p>results for: " + q + "</p>"\n'),
        "after":  ('def render_search(q):\n'
                   '    import html\n'
                   '    return "<p>results for: " + html.escape(q) + "</p>"\n'),
    },
    "idor": {
        "file": "app.py", "branch": "nullify/fix-idor",
        "title": "fix(security): IDOR in get_order",
        "before": ('def get_order(order_id, user, orders):\n'
                   '    return orders[order_id]\n'),
        "after":  ('def get_order(order_id, user, orders):\n'
                   '    o = orders[order_id]\n'
                   '    if o["owner"] != user:\n'
                   '        raise PermissionError("403")\n'
                   '    return o\n'),
    },
    "traversal": {
        "file": "app.py", "branch": "nullify/fix-traversal",
        "title": "fix(security): Path Traversal in read_file",
        "before": ('def read_file(name, webroot):\n'
                   '    return open(os.path.join(webroot, name)).read()\n'),
        "after":  ('def read_file(name, webroot):\n'
                   '    full = os.path.realpath(os.path.join(webroot, name))\n'
                   '    if not full.startswith(os.path.realpath(webroot) + os.sep):\n'
                   '        raise PermissionError("403")\n'
                   '    return open(full).read()\n'),
    },
    "cmdi": {
        "file": "app.py", "branch": "nullify/fix-cmdi",
        "title": "fix(security): Command Injection in ping",
        "before": ('def ping(host):\n'
                   '    return subprocess.run("ping " + host, shell=True,\n'
                   '                          capture_output=True, text=True).stdout\n'),
        "after":  ('def ping(host):\n'
                   '    return subprocess.run(["ping", host], shell=False,\n'
                   '                          capture_output=True, text=True).stdout\n'),
    },
    "redirect": {
        "file": "app.py", "branch": "nullify/fix-redirect",
        "title": "fix(security): Open Redirect in redirect_to",
        "before": ('def redirect_to(nxt):\n'
                   '    return {"Location": nxt}\n'),
        "after":  ('def redirect_to(nxt):\n'
                   '    if nxt.startswith("/") and not nxt.startswith("//"):\n'
                   '        return {"Location": nxt}\n'
                   '    return {"Location": "/"}\n'),
    },
    "ssrf": {
        "file": "app.py", "branch": "nullify/fix-ssrf",
        "title": "fix(security): SSRF in fetch_url",
        "before": ('def fetch_url(url):\n'
                   '    return urllib.request.urlopen(url).read()\n'),
        "after":  ('def fetch_url(url):\n'
                   '    low = url.lower()\n'
                   '    if any(k in low for k in ("127.0.0.1", "localhost", "169.254")):\n'
                   '        raise PermissionError("blocked internal target")\n'
                   '    return urllib.request.urlopen(url).read()\n'),
    },
}


def build_app_py():
    """카탈로그의 before 블록들을 모아 '사용자 레포의 app.py'를 만든다."""
    head = "import os\nimport subprocess\nimport urllib.request\n\n\n"
    return head + "\n\n".join(FIXES[k]["before"].rstrip() + "\n" for k in FIXES)
