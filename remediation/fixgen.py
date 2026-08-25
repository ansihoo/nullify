"""
수정 생성(fix generation) — 임의 레포의 코드에 맞는 패치를 도출한다.

역할 분리 (중요):
  - 검증(verify)에는 LLM 을 절대 쓰지 않는다 → 환각 방지, 결정론 유지.
  - '수정 생성'은 LLM 이 적절한 자리 → 임의 코드는 고정 규칙만으론 못 고친다.

안전 우선 3단 전략:
  1) 카탈로그(fixes.py)에 정확히 맞으면 그걸로   (github_pr.create_fix 가 먼저 시도)
  2) 아니면 LLM 으로 도출  (GEMINI_API_KEY 있을 때만 실제 호출)
  3) 둘 다 안 되면 '전문가 검토 필요' 로 정직하게 반환

※ 절대 원칙: LLM 이 만든 수정도 '재검증(closed loop)'을 통과하지 못하면 신뢰하지 않는다.
  생성은 추측일 수 있으나, 우리의 판정은 여전히 '실제로 다시 찔러봐서' 결정론으로 한다.

API 키는 이 코드가 읽기만 하고(os.environ) 절대 로그/반환에 담지 않는다.
"""
import os
import re
import ssl
import json
import urllib.request

try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except Exception:
    _SSL_CTX = ssl.create_default_context()

# Gemini REST API. 키는 os.environ 에서만 읽고 로그/반환에 절대 담지 않는다.
GEMINI_MODEL = os.environ.get("NULLIFY_FIX_MODEL", "gemini-3.6-flash")
GEMINI_URL = ("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent"
              % GEMINI_MODEL)


# 파일 확장자 → 코드펜스 언어 힌트(LLM 이 같은 언어로 답하도록).
_LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "jsx", ".ts": "typescript",
    ".tsx": "tsx", ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".sql": "sql", ".html": "html", ".vue": "vue",
}

def _lang_for(filename):
    import os
    _, ext = os.path.splitext(filename or "")
    return _LANG_BY_EXT.get(ext.lower(), "")

def build_prompt(source, kind, filename):
    lang = _lang_for(filename)
    fence = lang or ""
    return (
        "You are a security remediation tool. The file `%s` contains a %s vulnerability.\n"
        "Return ONLY the complete corrected file content, inside a single code block "
        "(```%s), with no commentary. Keep the SAME programming language as the input. "
        "Preserve all behavior except fixing the vulnerability.\n\n"
        "```%s\n%s\n```" % (filename, kind, fence, fence, source)
    )


def _extract_code(text):
    # 언어 태그가 뭐든(```python, ```tsx, ``` 등) 첫 코드블록을 뽑는다.
    m = re.search(r"```[a-zA-Z0-9]*\s*\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip()


def _call_gemini(key, prompt):
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": 4096, "temperature": 0.2},
    }).encode("utf-8")
    # 키는 헤더로 전달(x-goog-api-key) — URL 쿼리스트링에 넣지 않는다.
    req = urllib.request.Request(GEMINI_URL, data=body, headers={
        "x-goog-api-key": key,
        "content-type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=120, context=_SSL_CTX) as r:
        data = json.loads(r.read().decode("utf-8"))
    # Gemini 응답: candidates[0].content.parts[*].text
    out = []
    for cand in data.get("candidates", []):
        for part in cand.get("content", {}).get("parts", []):
            if "text" in part:
                out.append(part["text"])
    return "".join(out)


def generate_fix(source, kind, filename="app.py"):
    """(patched_source | None, note, source_tag) 반환."""
    # 파일이 너무 크면 앞 5000자만 보냄 (LLM 토큰 절약 + 타임아웃 방지)
    if len(source) > 5000:
        source = source[:5000] + "\n// ... (truncated)"
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        return None, "GEMINI_API_KEY 미설정 — LLM 수정 생성을 건너뜀(전문가 검토 필요)", "none"
    try:
        text = _call_gemini(key, build_prompt(source, kind, filename))
    except Exception as e:
        return None, "LLM 호출 실패: %s" % e, "none"
    patched = _extract_code(text)
    if not patched or patched.strip() == source.strip():
        return None, "LLM 이 유효한 수정을 제시하지 못함", "none"
    return patched, "LLM(%s) 생성 수정 — 재검증 필요" % GEMINI_MODEL, "llm"


if __name__ == "__main__":
    src = 'def get_user(i, db):\n    return db.execute("SELECT * FROM u WHERE id=\'"+i+"\'")\n'
    patched, note, tag = generate_fix(src, "sqli", "app.py")
    print("tag:", tag, "| note:", note)
    if patched:
        print(patched)
