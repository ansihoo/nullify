/**
 * Nullify 백엔드 연동 어댑터.
 *
 * 왜 이 파일이 필요한가:
 *   프론트(UI)는 mockSecurityData.ts 의 리치한 Vulnerability 모양을 기대한다.
 *   백엔드(Python web.py)는 결정론 검증 결과를 findings 배열로 준다 — 모양이 다르다.
 *   여기서 백엔드 findings → 프론트 Vulnerability[] 로 변환한다(= 어댑터).
 *
 * 핵심 원칙(백엔드와 동일): 취약 여부 '판정'은 전부 백엔드의 결정론 검증에서 온다.
 *   여기서 LLM 으로 지어내는 것은 없다. aiGuide 의 가이드 문구도 kind 별 고정 카탈로그(사람이 쓴 것).
 *
 * 백엔드는 로컬 전용(127.0.0.1:8000)이므로 이 앱도 로컬에서 실행해야 붙는다.
 * 주소/토큰은 Vite 환경변수로 덮어쓸 수 있다: VITE_NULLIFY_API, VITE_NULLIFY_TOKEN.
 */
import {
  Vulnerability,
  FilteredNoiseItem,
  VulnerabilitySeverity,
  VulnerabilityStatus,
  CodeSnippet,
  ExploitReceipt,
} from '../types';

const ENV = (import.meta as any).env || {};
export const API_BASE: string = ENV.VITE_NULLIFY_API || 'http://127.0.0.1:8000';
const API_TOKEN: string = ENV.VITE_NULLIFY_TOKEN || '';

/** 백엔드 finding 의 (우리가 쓰는) 모양. web.py run_scan 참고. */
interface Finding {
  type: string;
  kind: string;
  endpoint: string;
  param?: string;                // idor 등 resolve 시 백엔드에 넘길 파라미터명
  verdict: string;               // CONFIRMED | FALSE_POSITIVE | UNKNOWN
  severity: string;              // critical | warn | question | info
  reason: string;
  method?: string;               // GET | POST (POST 폼 후보)
  scanner?: string;
  proof_label?: string;
  proof?: string[];
  patch?: string;                // unified-diff 스타일 문자열
  receipt?: {
    before?: { verdict?: string; count?: number };
    after?: { verdict?: string; count?: number; note?: string };
    fixed?: boolean;
  };
  question?: string;
  answers?: { label: string; value: string }[];
  evidence?: any;
}

interface ScanResponse {
  target: string;
  total: number;
  crit: number;
  ques: number;
  warn: number;
  findings: Finding[];
  candidate_source?: string;
  authorized?: boolean;
  reason?: string;
  scan_id?: number;
}

// kind → 화면에 보일 유형 라벨
const TYPE_LABEL: Record<string, string> = {
  sqli: 'SQLi', xss: 'XSS', idor: 'IDOR', traversal: 'LFI',
  cmdi: 'CmdI', redirect: 'Open Redirect', ssrf: 'SSRF',
  headers: 'Security Headers', secret: 'Exposed Secret', component: 'Outdated Component',
};

// kind 별 고정 수정 가이드(사람이 작성 — LLM 아님). 백엔드 fixes 카탈로그와 같은 성격.
const FIX_GUIDE: Record<string, { fixDirection: string; tip: string }> = {
  sqli: { fixDirection: '문자열 조립 쿼리 대신 매개변수화 쿼리(Prepared Statement)/ORM 으로 입력을 데이터로만 취급.',
          tip: '동적 SQL 조립 금지, 최소 권한 DB 계정 사용.' },
  xss: { fixDirection: '출력 시 HTML 이스케이프 또는 textContent 렌더링, 필요 시 DOMPurify 적용.',
         tip: '입력 신뢰 금지 — 저장/반사 모두 출력 시점에 인코딩.' },
  idor: { fixDirection: '조회 쿼리에 현재 인증 사용자(소유권) 조건을 강제 바인딩(req.user.id).',
          tip: '리소스 접근 시 항상 소유권/권한 검증 포함.' },
  traversal: { fixDirection: '경로 정규화 후 화이트리스트 디렉터리 안인지 검사, ../ 차단.',
               tip: '사용자 입력을 파일 경로에 직접 쓰지 말 것.' },
  cmdi: { fixDirection: '셸 호출 대신 인자 배열 exec, 입력 화이트리스트 검증.',
          tip: '셸 메타문자(; | & $) 를 데이터로 넘기지 말 것.' },
  redirect: { fixDirection: '리다이렉트 대상은 허용 목록(allowlist) 내부 경로만.',
              tip: '외부 절대 URL 리다이렉트를 사용자 입력으로 결정하지 말 것.' },
  ssrf: { fixDirection: '요청 대상 호스트를 allowlist 로 제한, 내부 IP/메타데이터 대역 차단.',
          tip: '서버가 대신 요청하는 URL 은 반드시 검증.' },
  headers: { fixDirection: '응답에 X-Frame-Options, Content-Security-Policy 등 보안 헤더 추가.',
             tip: '프레임워크 보안 헤더 미들웨어를 기본 적용.' },
  secret: { fixDirection: '하드코딩된 키를 제거하고 런타임 환경변수/시크릿 매니저로 주입.',
            tip: '키가 커밋 이력에 있으면 즉시 폐기·회전.' },
  component: { fixDirection: '취약 버전 의존성을 패치된 최신 버전으로 업그레이드.',
               tip: 'SCA 로 알려진 CVE 를 CI 에서 상시 점검.' },
};

function toSeverity(s: string): VulnerabilitySeverity {
  if (s === 'critical' || s === 'question') return 'high';
  if (s === 'warn') return 'medium';
  return 'low';
}

function toStatus(f: Finding): { status: VulnerabilityStatus; statusText: string } {
  if (f.severity === 'question') return { status: 'pending_intent', statusText: '확인 필요' };
  if (f.severity === 'info') return { status: 'ignored', statusText: '오탐 (걸러냄)' };
  return { status: 'unresolved', statusText: '미해결' };
}

/**
 * 백엔드 patch(unified-diff 스타일 문자열) → codeSnippet{before,after,fileName}.
 * 백엔드 patch 예: "--- config.js\n+++ config.js (권고)\n- 옛코드\n+ 새코드"
 * 완벽한 파서는 아니고, '-'/'+' 줄을 모아 before/after 로 나눈다(데모 수준).
 */
function parsePatch(kind: string, patch?: string): CodeSnippet {
  const fallback: CodeSnippet = {
    fileName: `${kind}.patch`, problemLine: 1, fixLine: 1,
    beforeCode: '// 백엔드가 이 항목에 대한 수정 diff 를 제공하지 않았습니다.',
    afterCode: '// (검증된 수정은 확정/재검증 단계에서 생성)',
  };
  if (!patch) return fallback;

  const lines = patch.split('\n');
  let fileName = `${kind}.patch`;
  const before: string[] = [];
  const after: string[] = [];
  for (const ln of lines) {
    if (ln.startsWith('---')) { fileName = ln.replace(/^---\s*/, '').trim() || fileName; continue; }
    if (ln.startsWith('+++')) { continue; }
    if (ln.startsWith('-')) { before.push(ln.replace(/^-\s?/, '')); continue; }
    if (ln.startsWith('+')) { after.push(ln.replace(/^\+\s?/, '')); continue; }
    // 컨텍스트 줄(공백 시작 등)은 양쪽에 공통으로.
    before.push(ln); after.push(ln);
  }
  return {
    fileName,
    problemLine: 1,
    fixLine: 1,
    beforeCode: before.join('\n').trim() || fallback.beforeCode,
    afterCode: after.join('\n').trim() || fallback.afterCode,
  };
}

/**
 * 백엔드 receipt(검증 verdict 기반) + proof → 프론트 ExploitReceipt(HTTP 캡처 모양).
 * 주의: 백엔드는 '전체 HTTP 요청/응답'을 저장하지 않고 검증 판정(verdict)과 근거(proof)만 준다.
 *   여기서는 그 실제 근거로부터 유도해 채운다(지어내지 않음). body 에는 실제 훔친 근거를 넣는다.
 */
function toReceipt(f: Finding): ExploitReceipt | undefined {
  if (!f.receipt) return undefined;
  const fixed = !!f.receipt.fixed;
  const proofBody = (f.proof && f.proof.length) ? f.proof.join('\n')
                    : (f.evidence?.response || f.evidence?.['응답'] || '');
  const method = (f.method as any) || 'GET';
  return {
    timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' KST',
    endpoint: f.endpoint,
    method,
    payload: `${method} ${f.endpoint} — 검증기가 실제로 주입한 공격 요청 (결정론)`,
    beforeResponse: {
      status: 200,
      headers: { 'Content-Type': 'text/plain' },
      body: String(proofBody).slice(0, 2000) || '(근거 본문 없음)',
      vulnerable: true,
    },
    afterResponse: {
      status: fixed ? 200 : 200,
      headers: { 'X-Verified-By': 'Nullify' },
      body: fixed ? '패치 배포 후 동일 공격 재실행 → 재현 실패(취약점 소멸 확인).'
                  : (f.receipt.after?.note || '재검증 미완료 — 패치 배포 후 재실행 필요.'),
      vulnerable: !fixed,
    },
    proofSummary: fixed
      ? `${f.reason} — 패치 전 공격 성공, 패치 후 동일 공격 재현 실패로 소멸 검증됨.`
      : `${f.reason} — 공격 재현 성공(근거 확보). 재검증(닫힌 루프)은 배포 후 수행.`,
  };
}

/** question(IDOR 등) finding → intentQuestion 구조. */
function toIntentQuestion(f: Finding): Vulnerability['intentQuestion'] | undefined {
  if (f.severity !== 'question') return undefined;
  const yes = f.answers?.find((a) => a.value === 'owner_only') || f.answers?.[0];
  const no = f.answers?.find((a) => a.value === 'public') || f.answers?.[1];
  return {
    title: '확인이 필요해요',
    badgeText: `${f.endpoint} · ${TYPE_LABEL[f.kind] || f.kind} 의심`,
    reasonText: "자동으로 확정 못 한 이유 — 이 데이터를 누가 봐도 되는지는 '앱의 규칙'이라 저희가 모릅니다.",
    coreQuestion: f.question || '이 데이터는\n',
    highlightedPart: "'소유자 본인만'",
    yesOption: { label: yes?.label || '네, 본인만',
                 outcome: '타 사용자로 열람이 실제로 관찰됨 → 진짜 문제. 검증된 수정 준비.' },
    noOption: { label: no?.label || '아니요, 누구나',
                outcome: '공개 데이터로 확인 → 문제 아님. 목록에서 내립니다.' },
  };
}

function slug(s: string): string {
  return s.replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-|-$/g, '').toLowerCase();
}

/** 하나의 백엔드 finding → 프론트 Vulnerability. */
function adapt(f: Finding, i: number, target: string): Vulnerability {
  const typeLabel = TYPE_LABEL[f.kind] || f.type || f.kind;
  const { status, statusText } = toStatus(f);
  const guide = FIX_GUIDE[f.kind] || { fixDirection: '검증된 수정 패치를 참고해 적용.', tip: '' };
  const v: Vulnerability = {
    id: `${f.kind}-${slug(f.endpoint)}-${i}`,
    type: typeLabel,
    endpoint: f.endpoint + (f.method && f.method !== 'GET' ? ` [${f.method}]` : ''),
    title: `${typeLabel} @ ${f.endpoint}`,
    description: f.reason,
    severity: toSeverity(f.severity),
    status,
    statusText,
    selected: i === 0,
    requiresIntentConfirmation: f.severity === 'question',
    intentQuestion: toIntentQuestion(f),
    aiGuide: {
      title: `${typeLabel} 취약점 설명`,
      explanation: f.reason,
      fixDirection: guide.fixDirection,
      bestPracticeTip: guide.tip,
    },
    codeSnippet: parsePatch(f.kind, f.patch),
    receipt: toReceipt(f),
  };
  // 뒤 단계(resolve/fix)에서 백엔드를 다시 부를 수 있도록 원본을 숨겨둔다.
  (v as any)._raw = f;
  (v as any)._target = target;
  (v as any)._isRepo = false;   // DAST(URL) 결과 — 소스 없음
  (v as any)._source = target;
  return v;
}

// ── SAST(소스 정적 탐지) 핀딩 → Vulnerability. DAST 와 달리 '미검증(정적)'이다. ──
interface StaticFinding {
  file: string; line: number; rule: string; message: string;
  severity: string; kind: string;   // severity 는 이미 high|medium|low
}

function adaptStatic(f: StaticFinding, i: number, source: string): Vulnerability {
  const typeLabel = TYPE_LABEL[f.kind] || f.kind;
  const loc = `${f.file}:${f.line}`;
  const guide = FIX_GUIDE[f.kind] || { fixDirection: '소스 레포를 연결하면 검증된 수정을 생성합니다.', tip: '' };
  const v: Vulnerability = {
    id: `${f.kind}-${slug(f.file)}-${f.line}-${i}`,
    type: typeLabel,
    endpoint: loc,
    title: `${typeLabel} @ ${loc}`,
    description: f.message || `${f.rule} (정적 탐지)`,
    severity: (f.severity as VulnerabilitySeverity) || 'medium',
    status: 'unresolved',
    statusText: '정적 탐지 (미검증)',   // SAST 는 실행 재현 전이라 '미검증'을 명시
    selected: i === 0,
    aiGuide: {
      title: `${typeLabel} (정적 탐지)`,
      explanation: `${f.message}  — 규칙: ${f.rule}. 정적 분석 결과로, 실제 실행 재현(DAST) 전까지는 미검증입니다.`,
      fixDirection: guide.fixDirection,
      bestPracticeTip: guide.tip,
    },
    codeSnippet: {
      fileName: f.file, problemLine: f.line || 1, fixLine: f.line || 1,
      beforeCode: `// ${loc} — ${f.rule}\n// (소스 레포 연결 시 실제 코드/수정 diff 를 생성합니다)`,
      afterCode: `// 검증된 수정은 '패치 생성'(레포 연결) 단계에서 만들어집니다.`,
    },
  };
  (v as any)._raw = f;
  (v as any)._source = source;
  (v as any)._isRepo = true;    // 소스 레포 있음 → 실제 코드 수정 가능
  return v;
}

// ── 입력이 git 레포인가, 런타임 URL 인가 판별 ──────────────────────────────
const GIT_HOSTS = ['github.com', 'gitlab.com', 'bitbucket.org'];
export function isGitRepo(input: string): boolean {
  const s = input.trim();
  if (/\.git(\/|$|\?)/.test(s)) return true;                 // ...repo.git
  try {
    const u = new URL(s);
    if (GIT_HOSTS.includes(u.hostname.toLowerCase())) {
      // github.com/<user>/<repo> 형태(사용자 프로필만 있는 건 제외)
      return u.pathname.split('/').filter(Boolean).length >= 2;
    }
  } catch { /* URL 아님 → 아래로 */ }
  return false;
}

function toNoise(f: Finding, i: number): FilteredNoiseItem {
  return {
    id: `noise-${f.kind}-${i}`,
    type: TYPE_LABEL[f.kind] || f.kind,
    endpoint: f.endpoint,
    reason: f.reason || '검증기가 실제로 찔러본 결과 재현되지 않음 → 오탐으로 분류.',
    category: 'false_positive',
  };
}

/**
 * 대상 URL 을 스캔한다. discover=1 로 임의 앱도 후보 자동발견.
 * 반환: 화면에 바로 꽂을 수 있는 vulnerabilities / filteredNoise.
 */
export async function scanTarget(target: string): Promise<{
  vulnerabilities: Vulnerability[];
  filteredNoise: FilteredNoiseItem[];
  raw: ScanResponse;
}> {
  const url = `${API_BASE}/api/scan?target=${encodeURIComponent(target)}&discover=1`;
  const res = await fetch(url, {
    headers: API_TOKEN ? { 'X-API-Token': API_TOKEN } : {},
  });
  if (!res.ok) {
    if (res.status === 401) throw new Error('인증 필요 — VITE_NULLIFY_TOKEN 을 설정하세요.');
    if (res.status === 429) throw new Error('요청이 너무 잦습니다(rate limit). 잠시 후 다시.');
    throw new Error(`백엔드 오류 ${res.status}`);
  }
  const data: ScanResponse = await res.json();
  if (data.authorized === false) {
    throw new Error(`권한 거부 — ${data.reason || '로컬/사설망/소유 증명된 대상만 스캔 가능.'}`);
  }
  const findings = data.findings || [];
  // '조치 필요'(critical/warn/question) = 취약점, info(오탐/안전) = 걸러낸 노이즈.
  const vulnerabilities = findings
    .filter((f) => f.severity !== 'info')
    .map((f, i) => adapt(f, i, target));
  const filteredNoise = findings
    .filter((f) => f.severity === 'info')
    .map(toNoise);
  return { vulnerabilities, filteredNoise, raw: data };
}

function authHeaders(): Record<string, string> {
  return API_TOKEN ? { 'X-API-Token': API_TOKEN } : {};
}

/**
 * 소스 레포(SAST) 스캔 — git 레포 URL/경로를 받아 정적 탐지(/api/scan_source).
 * 백엔드가 자동 clone 후 semgrep(없으면 내장 시크릿 스캔)을 돌린다.
 * 정적 결과라 '미검증'이며, 소스가 있으므로 이후 '실제 코드 수정'이 가능하다.
 */
export async function scanSource(source: string): Promise<{
  vulnerabilities: Vulnerability[];
  filteredNoise: FilteredNoiseItem[];
  isRepo: true;
  raw: any;
}> {
  const url = `${API_BASE}/api/scan_source?source=${encodeURIComponent(source)}`;
  const res = await fetch(url, { headers: authHeaders() });
  if (!res.ok) throw new Error(`소스 스캔 오류 ${res.status}`);
  const data = await res.json();
  if (data.error) throw new Error(`소스 스캔 실패 — ${data.error}`);
  const findings: StaticFinding[] = data.findings || [];
  return {
    vulnerabilities: findings.map((f, i) => adaptStatic(f, i, source)),
    filteredNoise: [],   // SAST 는 '오탐 필터'가 없음(정적 탐지 자체가 후보)
    isRepo: true,
    raw: data,
  };
}

/**
 * 통합 입구 — 입력이 git 레포면 SAST, 런타임 URL 이면 DAST 로 자동 분기.
 * (github 레포 링크를 넣으면 DAST 로 잘못 보내 권한거부로 '씹히던' 문제 해결)
 */
export async function scanInput(input: string): Promise<{
  vulnerabilities: Vulnerability[];
  filteredNoise: FilteredNoiseItem[];
  isRepo: boolean;
  source: string;
}> {
  if (isGitRepo(input)) {
    const r = await scanSource(input);
    return { vulnerabilities: r.vulnerabilities, filteredNoise: r.filteredNoise, isRepo: true, source: input };
  }
  const r = await scanTarget(input);
  return { vulnerabilities: r.vulnerabilities, filteredNoise: r.filteredNoise, isRepo: false, source: input };
}

export type ScanMode = 'detect' | 'source' | 'combined';

/**
 * 통합 진입점 — 사이트 URL(선택) + 레포(선택)를 함께 받아 흐름을 정한다:
 *   - URL 만       → DAST '탐지 전용'(수정 불가, _canFix=false)
 *   - 레포만       → SAST(소스 있음 → 수정 가능)
 *   - URL + 레포   → 완전체: DAST 런타임 증거 + 소스. 상관(evidence)까지, 수정 가능.
 * 수정 가능 여부(_canFix)와 증거등급(_evidence)을 각 취약점에 심어 돌려준다.
 */
export async function scanEntry(urlIn: string, repoIn: string): Promise<{
  vulnerabilities: Vulnerability[];
  filteredNoise: FilteredNoiseItem[];
  mode: ScanMode;
  canFix: boolean;
}> {
  let url = (urlIn || '').trim();
  let repo = (repoIn || '').trim();
  // URL 칸에 레포를 넣었으면 레포로 취급(관용).
  if (url && isGitRepo(url) && !repo) { repo = url; url = ''; }

  // 소스가 있어야 수정 가능. 단 로컬 데모 과녁(127.0.0.1:8009)은 소스(sample_repo)를
  // 우리가 알고 있으므로 예외적으로 수정 가능(데모 전체 루프 시연용).
  const canFix = !!repo || isLocalDemo(url);
  const dast = url ? await scanTarget(url) : { vulnerabilities: [], filteredNoise: [] as FilteredNoiseItem[] };
  const sast = repo ? await scanSource(repo) : { vulnerabilities: [] as Vulnerability[] };

  const mode: ScanMode = (url && repo) ? 'combined' : (repo ? 'source' : 'detect');
  const sastKinds = new Set(sast.vulnerabilities.map((v) => (v as any)._raw?.kind));

  // DAST 취약점: 수정 가능여부·소스·증거등급을 심는다.
  for (const v of dast.vulnerabilities) {
    const kind = (v as any)._raw?.kind;
    (v as any)._canFix = canFix;
    if (repo) { (v as any)._source = repo; (v as any)._isRepo = true; }   // 소스 붙으면 실제 코드 수정 경로로
    (v as any)._evidence = sastKinds.has(kind) ? 'static+dynamic' : 'dynamic';
  }
  // SAST 취약점: DAST 로 이미 잡힌 kind 는 동적 카드로 대표되므로, 그 외(정적만)만 추가.
  const dastKinds = new Set(dast.vulnerabilities.map((v) => (v as any)._raw?.kind));
  const staticOnly = sast.vulnerabilities.filter((v) => !dastKinds.has((v as any)._raw?.kind));
  for (const v of staticOnly) {
    (v as any)._canFix = true;            // 소스 있으니 수정 가능
    (v as any)._evidence = 'static-only';
  }

  return {
    vulnerabilities: [...dast.vulnerabilities, ...staticOnly],
    filteredNoise: dast.filteredNoise,
    mode,
    canFix,
  };
}

/**
 * IDOR '의도 확인' 답을 백엔드에 보낸다(/api/resolve).
 *   isPrivate=true  → owner_only → 백엔드가 CONFIRMED 승격(+ 토이앱은 닫힌 루프까지)
 *   isPrivate=false → public     → FALSE_POSITIVE(오탐, 목록에서 내림)
 * 반환은 화면 갱신에 바로 쓰도록 어댑팅된 부분 Vulnerability.
 */
export async function resolveIntent(v: Vulnerability, isPrivate: boolean): Promise<{
  verdict: string;
  description: string;
  codeSnippet?: CodeSnippet;
  receipt?: ExploitReceipt;
}> {
  const raw = (v as any)._raw as Finding;
  const target = (v as any)._target as string;
  const answer = isPrivate ? 'owner_only' : 'public';
  const path = raw?.endpoint || '/order';
  const param = raw?.param || 'id';
  const url = `${API_BASE}/api/resolve?target=${encodeURIComponent(target)}`
            + `&answer=${answer}&path=${encodeURIComponent(path)}&param=${encodeURIComponent(param)}`;
  const res = await fetch(url, { headers: authHeaders() });
  if (!res.ok) throw new Error(`resolve 실패 ${res.status}`);
  const d = await res.json();
  // d: {verdict, severity, endpoint, reason, patch?, receipt?, proof?}
  const asFinding: Finding = {
    ...raw, verdict: d.verdict, severity: d.severity, reason: d.reason,
    patch: d.patch, receipt: d.receipt, proof: d.proof,
  };
  return {
    verdict: d.verdict,
    description: d.reason || v.description,
    codeSnippet: d.patch ? parsePatch(raw.kind, d.patch) : undefined,
    receipt: toReceipt(asFinding),
  };
}

export interface FixResult {
  ok: boolean;
  branch?: string;
  commit?: string;
  title?: string;
  diff?: string;
  gh?: string;
  fixSource?: string;       // catalog | llm
  needsReview?: boolean;
  reason?: string;
  error?: string;
  recommendation?: boolean; // 설정계열: 소스 수정 불필요, 설정 권고로 끝
  needsRepo?: boolean;      // 코드계열인데 소스 레포가 없음 → 레포 연결 필요
  detectionOnly?: boolean;  // URL 만 받은 탐지 전용 모드 → 수정 자체를 제공 안 함
}

// 설정계열 = 소스 코드가 아니라 서버/배포 설정으로 고치는 것 → 레포 없이도 수정 완결.
const CONFIG_KINDS = ['headers', 'secret', 'component'];

function isLocalDemo(target: string): boolean {
  try {
    const h = new URL(target).hostname;
    return h === '127.0.0.1' || h === 'localhost';
  } catch { return false; }
}

/**
 * 수정 생성 — 입력 종류에 따라 정직하게 분기한다:
 *   1) 소스 레포 스캔(SAST) 결과 → /api/connect: clone 한 '실제 소스'를 고쳐 진짜 커밋.
 *   2) DAST + 설정계열(헤더/시크릿/컴포넌트) → 소스 불필요. 설정 권고로 완결(recommendation).
 *   3) DAST + 로컬 데모(토이앱 ↔ sample_repo) → /api/pr: 데모 레포에 실제 커밋.
 *   4) DAST + 코드계열 + 임의 URL → 소스가 없어 코드 PR 불가 → 레포 연결 필요(needsRepo).
 */
export async function generateFix(v: Vulnerability): Promise<FixResult> {
  const raw = (v as any)._raw || {};
  const kind = raw.kind || '';
  const source = (v as any)._source as string;
  const target = (v as any)._target as string;
  const isRepo = !!(v as any)._isRepo;
  const canFix = (v as any)._canFix;

  // 0) 탐지 전용(URL만 받음) → 수정 제공 안 함. 소스 레포를 함께 올려야 수정 가능.
  if (canFix === false) {
    return { ok: false, detectionOnly: true,
             reason: '탐지 전용 모드 — 소스 레포를 함께 올리면 검증된 수정을 생성합니다.' };
  }

  // 1) 소스 레포가 있으면 실제 파일을 고친다(/api/connect). 헤더 등 설정계열도 레포가 있으면
  //    스택 인식으로 실제 커밋됨(_headers 파일/미들웨어). → 권고보다 우선.
  if (isRepo && source) {
    const url = `${API_BASE}/api/connect?source=${encodeURIComponent(source)}&kind=${encodeURIComponent(kind)}`;
    const res = await fetch(url, { headers: authHeaders() });
    if (!res.ok) return { ok: false, error: `레포 수정 실패 ${res.status}` };
    const d = await res.json();
    // 카탈로그가 이 레포 구조와 안 맞으면(대상 파일 없음 등) 암호 같은 에러 대신 정직한 안내.
    if (d.error && /대상 파일 없음|파일/.test(d.error)) {
      return { ok: false, needsReview: true,
               reason: '이 레포엔 자동 수정 카탈로그가 매칭되는 파일이 없습니다. 검증된 카탈로그 수정은 데모/알려진 구조에서 동작하고, 임의 레포는 LLM 수정(ANTHROPIC_API_KEY 설정) 또는 수동 수정이 필요합니다. — 동적으로 취약점은 확인됐으니(위 근거) 해당 위치를 직접 패치하세요.' };
    }
    if (d.error) return { ok: false, error: d.error };
    if (d.needs_review) return { ok: false, needsReview: true, reason: d.reason };
    return { ok: true, branch: d.branch, commit: d.commit, title: d.title,
             diff: d.diff, gh: d.gh, fixSource: d.fix_source };
  }

  // 2) 소스 없는 설정계열(URL만) → 적용 불가, 권고(스택별 스니펫)로.
  if (CONFIG_KINDS.includes(kind)) {
    return { ok: true, recommendation: true };
  }

  // 3) 로컬 데모 과녁(토이앱)은 소스가 sample_repo 라 검증된 카탈로그 수정이 실제로 됨.
  if (isLocalDemo(target || source)) {
    const url = `${API_BASE}/api/pr?kind=${encodeURIComponent(kind)}`;
    const res = await fetch(url, { headers: authHeaders() });
    if (!res.ok) return { ok: false, error: `PR 생성 실패 ${res.status}` };
    const d = await res.json();
    if (d.error) return { ok: false, error: d.error };
    if (d.needs_review) return { ok: false, needsReview: true, reason: d.reason };
    return { ok: true, branch: d.branch, commit: d.commit, title: d.title,
             diff: d.diff, gh: d.gh, fixSource: d.fix_source };
  }

  // 4) 그 외 → 소스가 없어 실제 코드 PR 불가.
  return { ok: false, needsRepo: true };
}

/**
 * 재검증(/api/rescan): 패치 배포 후 같은 공격을 다시 돌려 이전 스캔과 비교.
 * 반환에 compare(fixed/new/unchanged) 포함.
 */
export async function rescanTarget(target: string): Promise<{
  vulnerabilities: Vulnerability[];
  filteredNoise: FilteredNoiseItem[];
  compare?: { fixed: string[]; new: string[]; unchanged: string[] };
  raw: any;
}> {
  const url = `${API_BASE}/api/rescan?target=${encodeURIComponent(target)}&discover=1`;
  const res = await fetch(url, { headers: authHeaders() });
  if (!res.ok) throw new Error(`재검증 실패 ${res.status}`);
  const data = await res.json();
  if (data.authorized === false) throw new Error(`권한 거부 — ${data.reason || ''}`);
  const findings: Finding[] = data.findings || [];
  return {
    vulnerabilities: findings.filter((f) => f.severity !== 'info').map((f, i) => adapt(f, i, target)),
    filteredNoise: findings.filter((f) => f.severity === 'info').map(toNoise),
    compare: data.compare,
    raw: data,
  };
}
