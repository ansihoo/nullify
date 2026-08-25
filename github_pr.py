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

import fixgen
from fixes import FIXES, build_app_py


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


def create_fix(repo, kind, file_rel=None):
    """진짜 git 브랜치+커밋을 만들고 실제 diff 를 돌려준다.
       수정 도출: 카탈로그(결정론) → LLM(fixgen) → 전문가 검토, 순서로 시도.
       실제 GitHub push/PR 는 하지 않는다(사용자 토큰 필요) — 명령만 만들어 준다."""
    ensure_repo(repo)
    spec = FIXES.get(kind)
    file_rel = file_rel or (spec["file"] if spec else "app.py")
    branch = spec["branch"] if spec else "nullify/fix-" + kind
    title = spec["title"] if spec else "fix(security): " + kind
    path = os.path.join(repo, file_rel)
    if not os.path.exists(path):
        return {"kind": kind, "error": "대상 파일 없음: %s" % file_rel}

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
