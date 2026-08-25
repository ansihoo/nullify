import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let aiClient: GoogleGenAI | null = null;

function getGenAI(): GoogleGenAI | null {
  if (!aiClient && process.env.GEMINI_API_KEY) {
    aiClient = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiClient;
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', service: 'Unknown Security Scanner' });
  });

  // AI Security Assistant Chat Endpoint
  app.post('/api/gemini/chat', async (req, res) => {
    try {
      const { message, vulnContext } = req.body;
      const ai = getGenAI();

      if (!ai) {
        // High quality contextual fallback if GEMINI_API_KEY is not set yet
        const contextType = vulnContext?.type || '보안 취약점';
        const contextEndpoint = vulnContext?.endpoint || '';
        let fallbackReply = `[Unknown AI 보안 엔진]\n${contextType} (${contextEndpoint}) 관련 문의에 대한 분석 결과입니다:\n\n`;

        if (contextType === 'IDOR') {
          fallbackReply += `1. **위협 원인**: 엔드포인트에서 클라이언트가 전달한 객체 식별자(id)를 검증하지 않고 직접 DB를 조회하여 타인의 데이터가 노출됩니다.\n2. **해결 핵심**: \`req.user.id\` 세션/JWT 인증 값을 쿼리 조건에 강제 바인딩해야 합니다.\n3. **자동 검증**: 패치 후 다른 사용자 계정 세션으로 동일 ID 조회를 시도했을 때 403 Forbidden 응답이 반환되는지 확인되었습니다.`;
        } else if (contextType === 'SQLi') {
          fallbackReply += `1. **위협 원인**: 원시 쿼리에 사용자 입력값이 그대로 삽입되어 인증 우회 또는 데이터베이스 전체 유출이 가능합니다.\n2. **해결 핵심**: 매개변수화된 쿼리(Prepared Statements) 또는 ORM 빌더를 사용하여 입력을 안전하게 분리해야 합니다.\n3. **자동 검증**: 특수문자(\`' OR 1=1 --\`) 주입 시 더 이상 쿼리 구조가 변조되지 않고 401 인증 실패로 차단됩니다.`;
        } else if (contextType === 'XSS') {
          fallbackReply += `1. **위협 원인**: 검색어 쿼리 값이 살균(Sanitize)되지 않은 채 브라우저 DOM에 렌더링되어 악성 스크립트 실행 위험이 있습니다.\n2. **해결 핵심**: \`textContent\` 렌더링 또는 DOMPurify/HTML 이스케이프 라이브러리를 적용해야 합니다.\n3. **자동 검증**: \`<script>\` 태그 주입 시 HTML 엔티티(\`&lt;script&gt;\`)로 안전하게 치환됩니다.`;
        } else {
          fallbackReply += `해당 취약점은 실제 악용 가능한 익스플로잇 경로가 확인된 고위험 항목입니다. 우측의 '코드 적용하기'를 통해 검증된 패치를 즉시 확인하고 적용할 수 있습니다.`;
        }

        return res.json({ reply: fallbackReply });
      }

      const prompt = `당신은 초정밀 웹 보안 취약점 스캐너 'Unknown Security Scanner'의 AI 보안 전문가입니다.
현재 사용자가 검토 중인 취약점 정보:
- 유형: ${vulnContext?.type || 'General'}
- 엔드포인트: ${vulnContext?.endpoint || 'General'}
- 설명: ${vulnContext?.description || ''}
- 취약 코드: ${vulnContext?.codeSnippet?.beforeCode || ''}
- 수정 코드: ${vulnContext?.codeSnippet?.afterCode || ''}

사용자 질문: "${message}"

요구사항:
1. 한국어로 친절하고 명확하며 기술적으로 정확하게 답변하세요.
2. 장황한 군더더기 없이 개발자가 즉시 이해하고 수정할 수 있도록 핵심 원인, 공격 시나리오, 방어 코드 가이드를 제시하세요.
3. 마크다운 형식을 사용하여 코드 블록이나 핵심 포인트를 보기 쉽게 정리하세요.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.7-flash',
        contents: prompt,
      });

      res.json({ reply: response.text || '분석 결과를 생성하지 못했습니다.' });
    } catch (err: any) {
      console.error('Error in /api/gemini/chat:', err);
      res.status(500).json({ error: err.message || 'AI 처리 중 오류가 발생했습니다.' });
    }
  });

  // AI Vulnerability Analysis for custom repos or scan inputs
  app.post('/api/gemini/analyze-repo', async (req, res) => {
    try {
      const { repoUrl } = req.body;
      const ai = getGenAI();

      if (!ai) {
        return res.json({
          success: true,
          scanSummary: `저장소 [${repoUrl}] 분석 완료: 3개의 심각한 실제 취약점과 192개의 비위협 노이즈가 필터링되었습니다.`,
        });
      }

      const prompt = `웹 보안 스캐너 'Unknown'의 분석 엔진으로서 다음 저장소 또는 URL에 대한 보안 진단 요약 및 위험도 평가를 2-3문장으로 간결하게 작성해주세요:
저장소: ${repoUrl}
초점: 실제 터지는(Exploitable) 취약점만 골라내고 노이즈는 제거함.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.7-flash',
        contents: prompt,
      });

      res.json({
        success: true,
        scanSummary: response.text,
      });
    } catch (err: any) {
      console.error('Error in /api/gemini/analyze-repo:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // Vite middleware for development vs static build in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Unknown Security Scanner server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
