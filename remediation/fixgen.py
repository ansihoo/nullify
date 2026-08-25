"""
수정 생성(fix generation) — 임의 레포의 코드에 맞는 패치를 도출한다.

역할 분리 (중요):
  - 검증(verify)에는 LLM 을 절대 쓰지 않는다 → 환각 방지, 결정론 유지.
  - '수정 생성'은 LLM 이 적절한 자리 → 임의 코드는 고정 규칙만으론 못 고친다.

안전 우선 3단 전략:
  1) 카탈로그(fixes.py)에 정확히 맞으면 그걸로   (github_pr.create_fix 가 먼저 시도)
  2) 아니면 LLM 으로 도출  (ANTHROPIC_API_KEY 있을 때만 실제 호출)
  3) 둘 다 안 되면 '전문가 검토 필요' 로 정직하게 반환

※ 절대 원칙: LLM 이 만든 수정도 '재검증(closed loop)'을 통과하지 못하면 신뢰하지 않는다.
  생성은 추측일 수 있으나, 우리의 판정은 여전히 '실제로 다시 찔러봐서' 결정론으로 한다.

API 키는 이 코드가 읽기만 하고(os.environ) 절대 로그/반환에 담지 않는다.
"""
import os
import re
import json
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"


def build_prompt(source, kind, filename):
    return (
        "You are a security remediation tool. The file `%s` contains a %s vulnerability.\n"
        "Return ONLY the complete corrected file content, inside a single ```python code "
        "block, with no commentary. Preserve all behavior except fixing the vulnerability.\n\n"
        "```python\n%s\n```" % (filename, kind, source)
    )


def _extract_code(text):
    m = re.search(r"```(?:python)?\s*\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip()


def _call_anthropic(key, prompt, model):
    body = json.dumps({
        "model": model,
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(API_URL, data=body, headers={
        "x-api-key": key,
        "anthropic-version": API_VERSION,
        "content-type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read().decode("utf-8"))
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


def generate_fix(source, kind, filename="app.py"):
    """(patched_source | None, note, source_tag) 반환."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None, "ANTHROPIC_API_KEY 미설정 — LLM 수정 생성을 건너뜀(전문가 검토 필요)", "none"
    model = os.environ.get("NULLIFY_FIX_MODEL", "claude-sonnet-5")
    try:
        text = _call_anthropic(key, build_prompt(source, kind, filename), model)
    except Exception as e:
        return None, "LLM 호출 실패: %s" % e, "none"
    patched = _extract_code(text)
    if not patched or patched.strip() == source.strip():
        return None, "LLM 이 유효한 수정을 제시하지 못함", "none"
    return patched, "LLM(%s) 생성 수정 — 재검증 필요" % model, "llm"


if __name__ == "__main__":
    src = 'def get_user(i, db):\n    return db.execute("SELECT * FROM u WHERE id=\'"+i+"\'")\n'
    patched, note, tag = generate_fix(src, "sqli", "app.py")
    print("tag:", tag, "| note:", note)
    if patched:
        print(patched)
