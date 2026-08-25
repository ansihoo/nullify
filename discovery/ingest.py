"""
① 수집(Ingest) — 오픈소스 스캐너 리포트를 '후보 목록'으로 번역하는 어댑터.

- 우리는 스캐너를 다시 만들지 않는다. Nuclei / ZAP 같은 도구의 출력(JSON)을 입력으로 받는다.
- 여기선 Nuclei 스타일 JSONL(한 줄에 결과 하나)을 읽는다.
- 스캐너마다 형식이 달라도, 이 얇은 어댑터만 하나씩 두면 우리 내부 표준으로 통일된다.
  → 새 스캐너 지원 = 어댑터 파일 하나 추가.

핵심: 스캐너 출력에는 '오탐'이 잔뜩 섞여 있다. 우리는 그걸 후보로만 받고,
      진짜인지 아닌지는 뒤의 검증기(③)가 실제로 찔러서 결정한다.
"""
import json
import urllib.parse

# 스캐너의 태그/템플릿ID → 우리 검증기 종류(kind) 매핑.
KIND_KEYS = [("sqli", "sqli"), ("xss", "xss"),
             ("idor", "idor"), ("bola", "idor"), ("access-control", "idor"),
             ("traversal", "traversal"), ("lfi", "traversal"),
             ("cmdi", "cmdi"), ("command", "cmdi"), ("rce", "cmdi"),
             ("redirect", "redirect"),
             ("ssrf", "ssrf"),
             ("header", "headers"), ("misconfig", "headers"),
             ("secret", "secret"), ("exposure", "secret"),
             ("component", "component"), ("outdated", "component"), ("cve", "component")]


def kind_of(rec):
    tags = rec.get("info", {}).get("tags", [])
    hay = (rec.get("template-id", "") + " " + " ".join(tags)).lower()
    for key, kind in KIND_KEYS:
        if key in hay:
            return kind
    return None   # 우리가 검증기를 가진 종류가 아니면 버린다(여기선)


def load_candidates(path):
    cands = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            kind = kind_of(rec)
            if kind is None:
                continue
            u = urllib.parse.urlparse(rec.get("matched-at", ""))
            params = urllib.parse.parse_qs(u.query)
            param = next(iter(params), "")   # 첫 쿼리 파라미터 이름(id / q ...)
            cands.append({
                "kind": kind,
                "path": u.path,
                "param": param,
                "scanner": rec.get("info", {}).get("name", ""),   # 스캐너가 붙인 이름(=주장)
            })
    return cands


if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "scanner_report.jsonl"
    for c in load_candidates(p):
        print(c)
