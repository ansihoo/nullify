"""
상태 저장 + 사용자 계정(멀티테넌시).

- 스캔/이력/알림을 SQLite 에 저장하고, 전부 user_id 로 격리한다(내 것만 보임).
- 계정 인증은 토큰 기반. 토큰은 평문이 아니라 SHA-256 해시로 저장(보안 도구답게).
  발급 시에만 평문을 한 번 돌려주고, 이후엔 해시로만 대조한다.
- 계정 발급은 CLI:  python store.py adduser <이름>   → 토큰 1회 출력.
  (셀프 회원가입 UI 는 별도 인프라 — 여기선 운영자 발급 모델.)

인증 모드(web.py 가 판단):
  users 테이블에 사용자가 있으면 → 멀티유저(토큰→user 매핑).
  없고 NULLIFY_API_TOKEN 있으면   → 단일 토큰.
  둘 다 없으면                    → 개발 모드(열림, user_id=0).
"""
import os
import json
import time
import hashlib
import secrets
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nullify.db")


def _conn():
    c = sqlite3.connect(DB_PATH, timeout=5)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INT DEFAULT 0,
            ts TEXT, target TEXT,
            total INT, crit INT, ques INT, warn INT, dismissed INT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INT, type TEXT, endpoint TEXT, verdict TEXT,
            severity TEXT, kind TEXT, fixed INT, data TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS notifications(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INT DEFAULT 0,
            ts TEXT, target TEXT, scan_id INT, level TEXT, message TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE, token_hash TEXT UNIQUE, created TEXT)""")
        # 예전 DB 호환: 없으면 user_id 컬럼 추가
        for tbl in ("scans", "notifications"):
            try:
                c.execute("ALTER TABLE %s ADD COLUMN user_id INT DEFAULT 0" % tbl)
            except sqlite3.OperationalError:
                pass


# ---------- 사용자 계정 ----------
def _hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_user(name):
    """계정 생성 후 '평문 토큰'을 한 번만 돌려준다(이후엔 해시로만 저장)."""
    token = secrets.token_urlsafe(24)
    with _conn() as c:
        c.execute("INSERT INTO users(name,token_hash,created) VALUES(?,?,?)",
                  (name, _hash(token), time.strftime("%Y-%m-%d %H:%M:%S")))
    return token


def user_for_token(token):
    if not token:
        return None
    with _conn() as c:
        r = c.execute("SELECT id,name FROM users WHERE token_hash=?", (_hash(token),)).fetchone()
    return dict(r) if r else None


def any_users():
    with _conn() as c:
        return c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] > 0


def list_users():
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT id,name,created FROM users ORDER BY id").fetchall()]


# ---------- 스캔(사용자별 격리) ----------
def save_scan(result, user_id=0):
    total, crit, ques, warn = result["total"], result["crit"], result["ques"], result["warn"]
    dismissed = total - crit - ques - warn
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO scans(user_id,ts,target,total,crit,ques,warn,dismissed)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (user_id, time.strftime("%Y-%m-%d %H:%M:%S"), result["target"],
             total, crit, ques, warn, dismissed))
        sid = cur.lastrowid
        for f in result["findings"]:
            fixed = 1 if (f.get("receipt") or {}).get("fixed") else 0
            c.execute(
                "INSERT INTO findings(scan_id,type,endpoint,verdict,severity,kind,fixed,data)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (sid, f.get("type"), f.get("endpoint"), f.get("verdict"),
                 f.get("severity"), f.get("kind"), fixed, json.dumps(f, ensure_ascii=False)))
    return sid


def list_scans(user_id=0, limit=20):
    with _conn() as c:
        rows = c.execute("SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT ?",
                         (user_id, limit)).fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id, user_id=0):
    """소유자(user_id)의 스캔만 복원 — 남의 스캔은 못 본다."""
    with _conn() as c:
        s = c.execute("SELECT * FROM scans WHERE id=? AND user_id=?",
                      (scan_id, user_id)).fetchone()
        if not s:
            return None
        rows = c.execute("SELECT data FROM findings WHERE scan_id=? ORDER BY id",
                         (scan_id,)).fetchall()
    d = dict(s)
    d["findings"] = [json.loads(r["data"]) for r in rows]
    return d


def latest_scan_id_for(target, user_id=0):
    with _conn() as c:
        r = c.execute("SELECT id FROM scans WHERE target=? AND user_id=? ORDER BY id DESC LIMIT 1",
                      (target, user_id)).fetchone()
        return r["id"] if r else None


# ---------- 알림(사용자별 격리) ----------
def save_notification(target, scan_id, level, message, user_id=0):
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO notifications(user_id,ts,target,scan_id,level,message)"
            " VALUES(?,?,?,?,?,?)",
            (user_id, time.strftime("%Y-%m-%d %H:%M:%S"), target, scan_id, level, message))
        return cur.lastrowid


def list_notifications(user_id=0, limit=20):
    with _conn() as c:
        rows = c.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT ?",
                         (user_id, limit)).fetchall()
        return [dict(r) for r in rows]


if __name__ == "__main__":
    import sys
    init_db()
    if len(sys.argv) >= 3 and sys.argv[1] == "adduser":
        print("계정 '%s' 생성됨. 토큰(한 번만 표시):" % sys.argv[2])
        print("  " + create_user(sys.argv[2]))
    elif len(sys.argv) >= 2 and sys.argv[1] == "users":
        for u in list_users():
            print(u)
    else:
        print("사용법: python store.py adduser <이름>  |  python store.py users")
