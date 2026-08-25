"""
④ → PR : 검증된 수정을 GitHub PR 로 올리는 마지막 단계.

정직한 경계 (중요):
  실제 PR 생성 = 당신의 토큰 + 당신의 진짜 레포를 건드리는 외부 행위.
  → 이 모듈은 '그 직전까지'만 실제로 한다:
       새 브랜치 → 패치 실제 적용 → 커밋   (전부 로컬 git, 안전)
  → 마지막 push + PR 생성 '명령'만 만들어 돌려준다. 실행은 당신이 당신 토큰으로.

이 파일을 그냥 실행하면(python github_pr.py) 데모 레포에서 전 과정을 보여준다.
"""
import os
import textwrap
import tempfile
import subprocess

import remediation.fixgen as fixgen
from remediation.fixes import FIXES, build_app_py


def _git(repo, *args):
    r = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("git %s 실패: %s" % (" ".join(args), r.stderr.strip()))
    return r.stdout


def _commit(repo, msg):
    _git(repo, "-c", "user.email=nullify@local", "-c", "user.name=Nullify Bot",
         "-c", "commit.gpgsign=false", "commit", "-q", "-m", msg)


def ensure_repo(repo):
    """데모용 '사용자 레포'를 준비한다(없으면 생성 + git init + 최초 커밋)."""
    if os.path.isdir(os.path.join(repo, ".git")):
        return
    os.makedirs(repo, exist_ok=True)
    with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
        f.write(build_app_py())
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "-c", "user.email=dev@local", "-c", "user.name=Dev", "add", "app.py")
    _git(repo, "-c", "user.email=dev@local", "-c", "user.name=Dev",
         "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init app")


def connect_repo(source):
    """레포를 clone 해서 로컬 작업 사본 경로를 돌려준다.
       source: https URL(네트워크 필요) 또는 로컬 경로/file:// (데모).
       실제 사용자 레포를 '연결'하는 첫 단계 — 이후 create_fix 가 이 사본에 패치한다.
       ※ 임의 레포의 '정확한 패치'는 그 코드 분석이 필요(우리 카탈로그는 우리 샘플용).
         지금은 clone 파이프라인이 실제로 도는 것까지 보인다."""
    dest = tempfile.mkdtemp(prefix="nullify_clone_")
    r = subprocess.run(["git", "clone", "-q", source, dest], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("clone 실패: %s" % r.stderr.strip())
    return dest


# 추가할 보안 헤더(설정계열 자동수정 공통).
_SEC_HEADERS = [
    ("X-Frame-Options", "DENY"),
    ("Content-Security-Policy", "default-src 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
]


def _detect_stack(repo):
    """레포 파일로 스택을 결정론적으로 추정. (express | static)"""
    pkg = os.path.join(repo, "package.json")
    if os.path.exists(pkg):
        try:
            txt = open(pkg, encoding="utf-8").read()
            if '"express"' in txt:
                return "express"
        except OSError:
            pass
    return "static"   # 정적 호스팅(_headers 파일)로 폴백 — 가장 널리 통함


def _find_express_entry(repo):
    """`= express()` 가 있는 서버 진입 파일을 찾는다(node_modules 제외)."""
    import re
    rx = re.compile(r"=\s*express\(\)")
    for dirpath, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "dist", "build")]
        for name in files:
            if not name.endswith((".js", ".ts", ".mjs", ".cjs")):
                continue
            p = os.path.join(dirpath, name)
            try:
                if os.path.getsize(p) > 500_000:
                    continue
                src = open(p, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            if rx.search(src):
                return p, src
    return None, None


def create_headers_fix(repo):
    """보안 헤더 누락(설정계열)을 스택에 맞춰 실제로 고치고 커밋한다.
       express → setHeader 미들웨어 주입(의존성 추가 없음).
       그 외(정적/Vite 등) → public/_headers 파일 생성(Netlify/Cloudflare 형식)."""
    ensure_repo(repo)
    base = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip() or "main"
    branch = "nullify/fix-headers"
    title = "fix(security): 보안 헤더 추가 (X-Frame-Options, CSP 등)"
    _git(repo, "checkout", "-q", "-B", branch, base)

    stack = _detect_stack(repo)
    changed_rel = None

    if stack == "express":
        path, src = _find_express_entry(repo)
        if path:
            mw = ("\n// [VibeShield] 보안 헤더 추가\napp.use((req, res, next) => {\n"
                  + "".join("  res.setHeader('%s', %r);\n" % (h, v) for h, v in _SEC_HEADERS)
                  + "  next();\n});\n")
            # `const app = express();` 등 app 생성 줄 바로 뒤에 삽입.
            import re
            m = re.search(r".*=\s*express\(\).*\n", src)
            new = src[:m.end()] + mw + src[m.end():] if m else src + mw
            open(path, "w", encoding="utf-8").write(new)
            changed_rel = os.path.relpath(path, repo)
        else:
            stack = "static"   # express 인데 진입점 못 찾으면 정적 폴백

    if changed_rel is None:   # static (또는 express 폴백)
        import json as _json
        netlify = any(os.path.exists(os.path.join(repo, m))
                      for m in ("netlify.toml", os.path.join("public", "_redirects"), "_redirects"))
        if netlify:   # Netlify/Cloudflare Pages 는 public/_headers 를 읽는다.
            pub = os.path.join(repo, "public")
            os.makedirs(pub, exist_ok=True)
            body = "/*\n" + "".join("  %s: %s\n" % (h, v) for h, v in _SEC_HEADERS)
            open(os.path.join(pub, "_headers"), "w", encoding="utf-8").write(body)
            changed_rel = os.path.join("public", "_headers")
            stack = "static/netlify"
        else:   # Vercel(및 기본): vercel.json 의 headers. 기존 있으면 병합.
            vpath = os.path.join(repo, "vercel.json")
            try:
                conf = _json.load(open(vpath, encoding="utf-8")) if os.path.exists(vpath) else {}
                if not isinstance(conf, dict):
                    conf = {}
            except Exception:
                conf = {}
            conf["headers"] = [{
                "source": "/(.*)",
                "headers": [{"key": h, "value": v} for h, v in _SEC_HEADERS],
            }]
            open(vpath, "w", encoding="utf-8").write(_json.dumps(conf, ensure_ascii=False, indent=2) + "\n")
            changed_rel = "vercel.json"
            stack = "static/vercel"

    _git(repo, "add", changed_rel)
    _commit(repo, title)
    commit = _git(repo, "rev-parse", "--short", "HEAD").strip()
    diff = _git(repo, "show", "--no-color", "HEAD")
    _git(repo, "checkout", "-q", base)
    gh = ('git push -u origin %s\n'
          'gh pr create --base %s --head %s --title "%s" --body "VibeShield 보안 헤더 자동 수정"'
          % (branch, base, branch, title))
    return {"kind": "headers", "branch": branch, "commit": commit, "title": title,
            "diff": diff, "fix_source": "catalog(headers/%s)" % stack, "gh": gh}


def create_secret_fix(repo):
    """하드코딩된 시크릿(AWS 키 AKIA... 형태)을 소스에서 제거하고 커밋한다.
       완전체 스캔이면 레포가 있으니, 번들에 새는 하드코딩 키 리터럴을 실제로 지운다.
       → 재배포 후 번들에서 사라져 재검증이 FALSE_POSITIVE(죽음)로 확인된다."""
    import re
    ensure_repo(repo)
    base = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip() or "main"
    rx = re.compile(r"""(["'])AKIA[0-9A-Z]{12,}\1""")
    repl = '"" /* [VibeShield] 하드코딩 시크릿 제거 — 서버측/시크릿 매니저로 이전 */'

    # 1) 먼저 읽기만 해서 대상 파일을 찾는다(git 안 건드림).
    targets = []
    for dirpath, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "dist", "build")]
        for name in files:
            if not name.endswith((".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs")):
                continue
            p = os.path.join(dirpath, name)
            try:
                if os.path.getsize(p) > 2_000_000:
                    continue
                if rx.search(open(p, encoding="utf-8").read()):
                    targets.append(p)
            except (OSError, UnicodeDecodeError):
                continue

    if not targets:
        return {"kind": "secret", "needs_review": True,
                "reason": "하드코딩된 AWS 키(AKIA...)를 소스에서 찾지 못했습니다. 다른 형태의 시크릿은 수동 확인이 필요합니다."}

    # 2) 브랜치 만들고 실제로 치환·커밋.
    branch = "nullify/fix-secret"
    title = "fix(security): 하드코딩된 시크릿 제거"
    _git(repo, "checkout", "-q", "-B", branch, base)
    for p in targets:
        src = open(p, encoding="utf-8").read()
        open(p, "w", encoding="utf-8").write(rx.sub(repl, src))
        _git(repo, "add", os.path.relpath(p, repo))
    _commit(repo, title)
    commit = _git(repo, "rev-parse", "--short", "HEAD").strip()
    diff = _git(repo, "show", "--no-color", "HEAD")
    _git(repo, "checkout", "-q", base)
    gh = ('git push -u origin %s\n'
          'gh pr create --base %s --head %s --title "%s" --body "VibeShield 시크릿 제거 자동 수정"'
          % (branch, base, branch, title))
    return {"kind": "secret", "branch": branch, "commit": commit, "title": title,
            "diff": diff, "fix_source": "catalog(secret/hardcoded)", "gh": gh}


def create_fix(repo, kind, file_rel=None):
    """진짜 git 브랜치+커밋을 만들고 실제 diff 를 돌려준다.
       headers/secret 은 전용 자동수정 경로로 분기. 그 외는 카탈로그→LLM→검토 순."""
    if kind == "headers":
        return create_headers_fix(repo)
    if kind == "secret":
        return create_secret_fix(repo)
    ensure_repo(repo)
    spec = FIXES.get(kind)
    file_rel = file_rel or (spec["file"] if spec else "app.py")
    branch = spec["branch"] if spec else "nullify/fix-" + kind
    title = spec["title"] if spec else "fix(security): " + kind
    path = os.path.join(repo, file_rel)
    if not os.path.exists(path):
        # 기본 파일(app.py)이 없으면 레포에서 소스 파일을 자동 탐색해 LLM 수정 시도.
        _SRC_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php"}
        found = None
        for root, dirs, files in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "dist", "build", "__pycache__")]
            for fn in files:
                _, ext = os.path.splitext(fn)
                if ext.lower() in _SRC_EXTS:
                    candidate = os.path.join(root, fn)
                    # 파일 내용을 간단히 보고 취약 패턴이 있으면 우선 선택
                    try:
                        with open(candidate, encoding="utf-8", errors="replace") as cf:
                            content = cf.read(10000)
                        if found is None:
                            found = (candidate, content)
                        # kind 에 맞는 힌트가 있으면 이걸로 확정
                        hints = {"sqli": ["execute", "query", "sql"], "xss": ["innerHTML", "dangerouslySetInnerHTML", "v-html"],
                                 "secret": ["API_KEY", "SECRET", "PASSWORD", "AKIA"], "headers": ["helmet", "Content-Security"],
                                 "traversal": ["readFile", "open(", "path.join"], "cmdi": ["exec(", "spawn(", "system("]}
                        for h in hints.get(kind, []):
                            if h.lower() in content.lower():
                                found = (candidate, content)
                                break
                    except Exception:
                        pass
        if not found:
            return {"kind": kind, "error": "대상 파일 없음: %s — 레포에 소스 파일을 찾지 못함" % file_rel}
        path, src_content = found
        file_rel = os.path.relpath(path, repo)
        # 카탈로그 매칭 건너뛰고 바로 LLM 수정 시도
        patched, note, tag = fixgen.generate_fix(src_content, kind, file_rel)
        if not patched:
            _git(repo, "checkout", "-q", "main")
            return {"kind": kind, "needs_review": True, "reason": note}
        _git(repo, "checkout", "-q", "-B", branch, "main")
        with open(path, "w", encoding="utf-8") as f:
            f.write(patched)
        _git(repo, "add", file_rel)
        _commit(repo, title)
        commit = _git(repo, "rev-parse", "--short", "HEAD").strip()
        base = "main"
        diff = _git(repo, "show", "--no-color", "HEAD")
        _git(repo, "checkout", "-q", base)
        gh = ("git push -u origin %s\n"
              "gh pr create --base %s --head %s --title \"%s\" --body \"Nullify LLM 자동 수정\"" 
              % (branch, base, branch, title))
        return {"kind": kind, "ok": True, "branch": branch, "commit": commit,
                "title": title, "diff": diff, "fix_source": tag, "gh": gh}

    _git(repo, "checkout", "-q", "-B", branch, "main")
    with open(path, encoding="utf-8") as f:
        src = f.read()

    if spec and spec["before"] in src:                     # 1) 카탈로그(결정론)
        new, fix_source = src.replace(spec["before"], spec["after"], 1), "catalog"
    else:                                                  # 2) LLM 도출
        patched, note, tag = fixgen.generate_fix(src, kind, file_rel)
        if not patched:                                    # 3) 전문가 검토
            _git(repo, "checkout", "-q", "main")
            return {"kind": kind, "needs_review": True, "reason": note}
        new, fix_source = patched, tag

    with open(path, "w", encoding="utf-8") as f:
        f.write(new)
    _git(repo, "add", file_rel)
    _commit(repo, title)
    commit = _git(repo, "rev-parse", "--short", "HEAD").strip()
    diff = _git(repo, "show", "--no-color", "HEAD")
    _git(repo, "checkout", "-q", "main")
    gh = ('git push -u origin %s\n'
          'gh pr create --base main --head %s --title "%s" --body "Nullify 검증된 수정"'
          % (branch, branch, title))
    return {"kind": kind, "branch": branch, "commit": commit, "title": title,
            "diff": diff, "fix_source": fix_source, "gh": gh}


def prepare_pr(repo, file_rel, old_code, new_code, branch, commit_msg):
    """로컬에서 브랜치 생성 + 패치 실제 적용 + 커밋. 실제 git diff 를 돌려준다."""
    _git(repo, "checkout", "-B", branch)
    path = os.path.join(repo, file_rel)
    with open(path, encoding="utf-8") as f:
        src = f.read()
    if old_code not in src:
        raise RuntimeError("취약 코드 조각을 파일에서 찾지 못함 — 패치 적용 불가")
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(old_code, new_code, 1))
    _git(repo, "add", file_rel)
    _git(repo, "-c", "user.email=nullify@local", "-c", "user.name=Nullify Bot",
         "-c", "commit.gpgsign=false", "commit", "-m", commit_msg)
    return _git(repo, "show", "--no-color", "HEAD")


def pr_metadata(finding):
    """검증 결과(finding)로 PR 제목/본문을 만든다. 본문에 '영수증'을 박는다."""
    r = finding["receipt"]
    title = "fix(security): %s in %s" % (finding["type"], finding["endpoint"])
    body = textwrap.dedent("""\
        ## Nullify 자동 수정 — 검증된 패치

        - **취약점**: {t}  (`{ep}`)
        - **증거 (before)**: {pl} — {proof}
        - **재검증 (after)**: {av} · 유출 {ac}건  {ok}

        이 수정은 실제로 공격을 재현한 뒤, 패치 적용 후 **같은 공격이 실패하는 것**을 확인하여
        생성되었습니다. 정적 추론이 아니라 런타임 증거 기반입니다.
        """).format(t=finding["type"], ep=finding["endpoint"],
                    pl=finding["proof_label"], proof=", ".join(finding["proof"]),
                    av=r["after"]["verdict"], ac=r["after"]["count"],
                    ok=("✅ 취약점 소멸 확인" if r["fixed"] else ""))
    return title, body


def push_and_pr_command(branch):
    """실행은 사용자가(gh CLI + 사용자 인증). 여기서 실행하지 않는다."""
    return ("git push -u origin %s\n"
            "gh pr create --base main --head %s --title <제목> --body-file PR_BODY.md"
            % (branch, branch))


# ---- 데모용 취약/안전 코드 조각 (실제로는 당신 레포의 파일) ----
VULN_BLOCK = ('    sql = "SELECT id, name FROM users WHERE id=\'" + id_value + "\'"\n'
              '    return db.execute(sql).fetchall()\n')
SAFE_BLOCK = ('    sql = "SELECT id, name FROM users WHERE id=?"\n'
              '    return db.execute(sql, (id_value,)).fetchall()\n')
SAMPLE_APP = "def get_user(id_value, db):\n" + VULN_BLOCK


if __name__ == "__main__":
    repo = tempfile.mkdtemp(prefix="nullify_repo_")
    with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
        f.write(SAMPLE_APP)
    _git(repo, "init", "-q")
    _git(repo, "-c", "user.email=dev@local", "-c", "user.name=Dev", "add", "app.py")
    _git(repo, "-c", "user.email=dev@local", "-c", "user.name=Dev",
         "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init")

    finding = {  # web.py 의 scan 결과에서 오는 형태(요약)
        "type": "SQL Injection", "endpoint": "/user",
        "proof_label": "훔친 secret",
        "proof": ["alice-secret", "bob-secret", "carol-secret"],
        "receipt": {"after": {"verdict": "FALSE_POSITIVE", "count": 0}, "fixed": True}}

    branch = "nullify/fix-sqli-user"
    diff = prepare_pr(repo, "app.py", VULN_BLOCK, SAFE_BLOCK, branch,
                      "fix(security): SQL Injection in /user")
    title, body = pr_metadata(finding)

    print("레포:", repo)
    print("\n=== 실제 적용된 커밋 (로컬 git show) ===")
    print(diff)
    print("=== PR 제목 ===\n" + title)
    print("\n=== PR 본문 ===\n" + body)
    print("=== 실행은 당신이 (당신 토큰) ===")
    print(push_and_pr_command(branch))
    print("\n※ 위 push/PR 명령은 여기서 실행하지 않음 — 당신의 인증과 실제 레포가 필요.")
