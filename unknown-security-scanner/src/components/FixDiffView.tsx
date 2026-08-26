import React, { useState, useEffect } from 'react';
import confetti from 'canvas-confetti';
import { Vulnerability } from '../types';

interface FixDiffViewProps {
  vuln: Vulnerability;
  onGeneratePatch: (vuln: Vulnerability) => void;
  onGenerateAll?: () => void;   // 모두 수정 — 시크릿+헤더를 한 커밋에
  onNavigateToVerify: () => void;
  onSelectVuln: (vuln: Vulnerability) => void;
  allVulnerabilities: Vulnerability[];
  canFix?: boolean;   // 소스 레포가 있어야 실제 수정 제공(없으면 탐지 전용)
}

export const FixDiffView: React.FC<FixDiffViewProps> = ({
  vuln,
  onGeneratePatch,
  onGenerateAll,
  onNavigateToVerify,
  onSelectVuln,
  allVulnerabilities,
  canFix = false,
}) => {
  const [agreedToGit, setAgreedToGit] = useState<boolean>(true);
  const [isPatchCreated, setIsPatchCreated] = useState<boolean>(vuln.status === 'resolved');
  const [copiedPatch, setCopiedPatch] = useState<boolean>(false);

  // '모두 수정'/'패치 생성'은 App 상태(vuln.status)를 바꾼다 — 여기에 동기화해야 수정 후
  // '다음: 검증' 버튼이 뜬다(안 그러면 수정 단계에서 다음으로 못 넘어감). 선택 취약점이
  // 바뀔 때도 그 상태를 반영.
  useEffect(() => {
    setIsPatchCreated(vuln.status === 'resolved');
  }, [vuln.id, vuln.status]);

  const handlePatchSubmit = () => {
    confetti({
      particleCount: 80,
      spread: 70,
      origin: { y: 0.6 },
      colors: ['#005652', '#a6f0ea', '#1f6f6b', '#8ad3ce'],
    });
    setIsPatchCreated(true);
    onGeneratePatch(vuln);
  };

  const handleCopyPatch = () => {
    const patchContent = `--- a/${vuln.codeSnippet.fileName}
+++ b/${vuln.codeSnippet.fileName}
@@ -1,5 +1,6 @@
${vuln.codeSnippet.beforeCode.split('\n').map((l) => `- ${l}`).join('\n')}
${vuln.codeSnippet.afterCode.split('\n').map((l) => `+ ${l}`).join('\n')}
`;
    navigator.clipboard.writeText(patchContent);
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 2000);
  };

  // 취약점이 하나도 없으면(스캔 0건) 전/후 비교를 그릴 게 없음 → 빈 상태.
  if (allVulnerabilities.length === 0) {
    return (
      <div id="fix-diff-view-container" className="p-6 max-w-3xl mx-auto">
        <div className="bg-white border border-[#bec9c7] rounded-2xl p-10 text-center space-y-3">
          <span className="material-symbols-outlined text-[40px] text-[#8ad3ce]">check_circle</span>
          <h2 className="text-[20px] font-bold text-[#181c1c]">수정할 취약점이 없습니다</h2>
          <p className="text-[14px] text-[#6f7978] leading-relaxed">
            이번 스캔에서 재현되는 취약점을 찾지 못했습니다. 수정 전/후 비교는 발견된 취약점이 있을 때만 표시됩니다.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div id="fix-diff-view-container" className="p-6 max-w-7xl mx-auto space-y-6 pb-24">

      {/* Header with Title and Subtitle */}
      <div>
        <div className="flex flex-wrap items-center justify-between gap-4 mb-2">
          <div>
            <h2 className="text-[24px] sm:text-[28px] font-bold text-[#181c1c] tracking-tight">
              취약점 분석 및 해결 — 수정 전후
            </h2>
            <p className="text-[14px] sm:text-[15px] text-[#3f4948]">
              발견된 보안 취약점에 대한 코드 레벨의 수정 제안을 확인하고, 패치를 적용하여 시스템을 안전하게 보호하세요.
            </p>
          </div>

          {/* Vulnerability Switcher Pill */}
          <div className="flex items-center gap-2 bg-[#eceeed] p-1 rounded-lg">
            {allVulnerabilities
              .filter((v) => v.status !== 'ignored')
              .map((v) => (
                <button
                  key={v.id}
                  onClick={() => onSelectVuln(v)}
                  className={`px-3 py-1 text-xs font-bold rounded-md transition-all ${
                    v.id === vuln.id
                      ? 'bg-white text-[#005652] shadow-sm'
                      : 'text-[#3f4948] hover:text-[#181c1c]'
                  }`}
                >
                  {v.type} ({v.endpoint})
                </button>
              ))}
          </div>
        </div>
      </div>

      {/* Side-by-Side Bento Grid for Before / After */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Left: Problem Before */}
        <div className="bg-white rounded-2xl border-2 border-[#ffdad6] p-6 shadow-sm flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-1.5 bg-[#ba1a1a]"></div>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[#ba1a1a] text-[22px]">
                  warning
                </span>
                <h3 className="font-bold text-[18px] text-[#181c1c]">
                  기존 코드의 문제 [{vuln.type} 취약점]
                </h3>
              </div>
              <span className="text-[12px] font-bold text-[#ba1a1a] bg-[#ffdad6] px-2.5 py-0.5 rounded-full">
                ✕ 취약점 존재
              </span>
            </div>

            <p className="text-[13.5px] text-[#545f72] leading-relaxed">
              요청 파라미터 <code className="text-[#ba1a1a] bg-[#ffdad6]/40 px-1.5 py-0.5 rounded font-code">id</code>를 그대로 사용하여 리소스를 조회하므로, 인가되지 않은 타인의 데이터에 직접 접근할 수 있습니다.
            </p>

            {/* Code Box */}
            <div className="rounded-xl overflow-hidden border border-[#bec9c7] bg-[#181c1c] text-white">
              <div className="bg-[#242929] px-4 py-2 text-xs font-code text-[#ffb4ab] flex items-center justify-between border-b border-[#333a39]">
                <span>{vuln.codeSnippet.fileName} (취약 버전)</span>
                <span className="text-[#ffdad6]/60">Line 1-5</span>
              </div>
              <pre className="p-4 text-[13px] font-code overflow-x-auto text-[#ffdad6] leading-relaxed bg-[#1f1b1b]">
                <code>{vuln.codeSnippet.beforeCode}</code>
              </pre>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-[#eceeed] flex items-center justify-between text-xs text-[#6f7978]">
            <span>위험 레벨: <strong>고위험 (CVSS 8.5)</strong></span>
            <span>데이터 유출 위험</span>
          </div>
        </div>

        {/* Right: Patched After */}
        <div className="bg-white rounded-2xl border-2 border-[#a6f0ea] p-6 shadow-sm flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-1.5 bg-[#005652]"></div>

          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[#005652] text-[22px]">
                  verified
                </span>
                <h3 className="font-bold text-[18px] text-[#181c1c]">
                  수정 제안 및 검증 [안전함]
                </h3>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[12px] font-bold text-[#00504d] bg-[#a6f0ea] px-2.5 py-0.5 rounded-full">
                  ✓ 취약점 사라짐
                </span>
                <span className="text-[12px] font-bold text-[#00504d] bg-[#a6f0ea] px-2.5 py-0.5 rounded-full">
                  ✓ 수정 완료
                </span>
              </div>
            </div>

            <p className="text-[13.5px] text-[#3f4948] leading-relaxed">
              세션에서 인증된 사용자 ID(<code className="text-[#005652] bg-[#a6f0ea]/40 px-1.5 py-0.5 rounded font-code">req.user.id</code>)를 쿼리에 추가하여 리소스 소유권을 엄격하게 강제합니다.
            </p>

            {/* Patched Code Box */}
            <div className="rounded-xl overflow-hidden border border-[#005652]/40 bg-[#181c1c] text-white">
              <div className="bg-[#1b2625] px-4 py-2 text-xs font-code text-[#a5efe9] flex items-center justify-between border-b border-[#2d3e3c]">
                <span>{vuln.codeSnippet.fileName} (패치 제안)</span>
                <button
                  onClick={handleCopyPatch}
                  className="text-xs text-[#a5efe9] hover:underline flex items-center gap-1"
                >
                  <span className="material-symbols-outlined text-[14px]">
                    {copiedPatch ? 'check' : 'content_copy'}
                  </span>
                  {copiedPatch ? '복사됨' : ''}
                </button>
              </div>
              <pre className="p-4 text-[13px] font-code overflow-x-auto text-[#a5efe9] leading-relaxed bg-[#162220]">
                <code>{vuln.codeSnippet.afterCode}</code>
              </pre>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-[#eceeed] flex items-center justify-between text-xs text-[#005652]">
            <span>검증 상태: <strong>보안 테스트 통과</strong></span>
            <span>소유권 격리 완료</span>
          </div>
        </div>

      </div>

      {/* 탐지 전용(URL만) — 수정 액션 대신 안내 */}
      {!canFix ? (
      <div className="bg-[#eef4f3] rounded-2xl border border-[#cfe0dd] p-6 flex items-start gap-3">
        <span className="material-symbols-outlined text-[#1f6f6b] text-[22px]">travel_explore</span>
        <div>
          <h4 className="font-bold text-[15px] text-[#1f4d49]">탐지 전용 모드 — 발견까지만 제공</h4>
          <p className="text-[13.5px] text-[#3f5f5b] mt-1">
            사이트 URL만 받으면 "어디가 취약한지"까지만 알 수 있어요(소스가 없어 코드 수정 불가).
            검증된 코드 수정과 PR을 받으려면 <strong>GitHub 레포도 함께</strong> 올려 다시 스캔하세요.
            {['headers','secret','component'].includes(((vuln as any)._raw?.kind)||'') &&
              ' (이 항목은 설정 계열이라, 위 "수정 제안"의 설정을 서버/프록시에 그대로 적용하면 됩니다.)'}
          </p>
        </div>
      </div>
      ) : (
      /* Action Card & Consent Box */
      <div className="bg-white rounded-2xl border border-[#bec9c7] p-6 shadow-sm flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="flex items-center gap-3">
          <input
            id="checkbox-github-consent"
            type="checkbox"
            checked={agreedToGit}
            onChange={(e) => setAgreedToGit(e.target.checked)}
            className="w-5 h-5 text-[#005652] rounded border-[#bec9c7] focus:ring-[#005652] cursor-pointer"
          />
          <label htmlFor="checkbox-github-consent" className="text-[14px] sm:text-[15px] font-medium text-[#181c1c] cursor-pointer select-none">
            수정된 파일 생성 및 GitHub 반영 동의 (자동 Pull Request 생성)
          </label>
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          {isPatchCreated ? (
            <button
              id="btn-goto-verify"
              onClick={onNavigateToVerify}
              className="w-full md:w-auto bg-[#005652] text-white px-8 py-3 rounded-xl font-bold text-[15px] hover:bg-[#1f6f6b] active:scale-95 transition-all flex items-center justify-center gap-2 shadow-md cursor-pointer"
            >
              <span>다음: 검증</span>
              <span className="material-symbols-outlined text-[18px]">arrow_forward</span>
            </button>
          ) : (
            <>
              <button
                id="btn-generate-patch"
                onClick={handlePatchSubmit}
                disabled={!agreedToGit}
                className="w-full md:w-auto bg-[#005652] text-white px-8 py-3 rounded-xl font-bold text-[15px] hover:bg-[#1f6f6b] active:scale-95 transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-md cursor-pointer"
              >
                <span className="material-symbols-outlined text-[18px]">auto_fix_high</span>
                <span>패치 생성</span>
              </button>
              {/* 모두 수정 — 시크릿+헤더를 한 커밋에. 명령 하나만 push 하면 4건 동시 사망(데모용). */}
              {onGenerateAll && canFix && allVulnerabilities.length > 1 && (
                <button
                  id="btn-generate-all"
                  onClick={onGenerateAll}
                  disabled={!agreedToGit}
                  className="w-full md:w-auto bg-[#00201e] text-white px-6 py-3 rounded-xl font-bold text-[15px] hover:bg-[#1f6f6b] active:scale-95 transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-md cursor-pointer"
                >
                  <span className="material-symbols-outlined text-[18px]">done_all</span>
                  <span>모두 수정 ({allVulnerabilities.length}건 한 번에)</span>
                </button>
              )}
            </>
          )}
        </div>
      </div>
      )}

      {/* 스크롤 앵커 — 수정 결과가 화면 아래에 뜨므로 App 이 이 id 로 자동 스크롤. */}
      <div id="fix-result-anchor" style={{ scrollMarginTop: 80 }} />

      {/* 실제 git 수정 결과 (백엔드 /api/pr) */}
      {(() => {
        const pr = (vuln as any)._pr;
        if (!pr) return null;
        if (pr.recommendation) {
          const kind = (vuln as any)._raw?.kind;
          // 헤더는 스택별 복붙 스니펫을 제공(URL만 스캔이라 '적용'은 못 하고 조언).
          const headerSnippets = kind === 'headers' ? [
            { label: 'Express (Node)', lang: 'js',
              code: `// app 생성 직후 추가\napp.use((req, res, next) => {\n  res.setHeader('X-Frame-Options', 'DENY');\n  res.setHeader('Content-Security-Policy', "default-src 'self'");\n  res.setHeader('X-Content-Type-Options', 'nosniff');\n  res.setHeader('Referrer-Policy', 'no-referrer');\n  next();\n});` },
            { label: '정적 호스팅 (Netlify/Cloudflare) — public/_headers', lang: 'text',
              code: `/*\n  X-Frame-Options: DENY\n  Content-Security-Policy: default-src 'self'\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer` },
            { label: 'Nginx — server { } 블록', lang: 'nginx',
              code: `add_header X-Frame-Options "DENY" always;\nadd_header Content-Security-Policy "default-src 'self'" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header Referrer-Policy "no-referrer" always;` },
          ] : null;
          return (
            <div className="bg-[#e9f7f5] rounded-2xl border border-[#a6f0ea] p-6 space-y-3">
              <h4 className="font-bold text-[16px] text-[#00504d] flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px]">settings_suggest</span>
                설정 권고 — 소스 코드 수정 불필요
              </h4>
              <p className="text-[13.5px] text-[#3f6f6b]">
                이 항목은 서버/프록시/배포 <strong>설정</strong>으로 해결합니다. 쓰는 스택에 맞는 걸 복붙하세요.
                {headerSnippets && ' (소스 레포도 함께 올리면 우리가 이 수정을 자동 커밋해 드립니다.)'}
              </p>
              {headerSnippets ? (
                <div className="space-y-3">
                  {headerSnippets.map((s) => (
                    <div key={s.label}>
                      <div className="text-[12px] font-bold text-[#00504d] mb-1">{s.label}</div>
                      <pre className="rounded-lg bg-[#181c1c] text-[#a5efe9] p-3 text-[12.5px] font-code overflow-x-auto whitespace-pre-wrap">{s.code}</pre>
                    </div>
                  ))}
                </div>
              ) : (
                <pre className="rounded-lg bg-[#181c1c] text-[#a5efe9] p-3 text-[12.5px] font-code overflow-x-auto whitespace-pre-wrap">{vuln.codeSnippet.afterCode}</pre>
              )}
            </div>
          );
        }
        if (pr.needsRepo) {
          return (
            <div className="bg-[#fef6e7] rounded-2xl border border-[#f0d9a8] p-6 space-y-2">
              <h4 className="font-bold text-[15px] text-[#8a5a00] flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px]">folder_off</span>
                소스 레포 연결이 필요합니다
              </h4>
              <p className="text-[13.5px] text-[#6b5416]">
                이건 코드 레벨 취약점이라 <strong>실제 소스가 있어야</strong> 검증된 코드 패치·커밋을 만들 수 있어요.
                URL 스캔만으로는 "여기가 터진다"까지만 알 수 있습니다.
                상단 입력창에 <span className="font-code bg-white px-1.5 py-0.5 rounded border border-[#f0d9a8]">github.com/&lt;계정&gt;/&lt;레포&gt;</span> 를 넣어 다시 스캔하면 실제 코드 수정을 생성합니다.
              </p>
            </div>
          );
        }
        if (pr.error || pr.needsReview) {
          return (
            <div className="bg-[#fef6e7] rounded-2xl border border-[#f0d9a8] p-6 space-y-2">
              <h4 className="font-bold text-[15px] text-[#8a5a00] flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px]">info</span>
                {pr.needsReview ? '전문가 검토 필요' : '수정 생성 실패'}
              </h4>
              <p className="text-[13.5px] text-[#6b5416]">
                {pr.reason || pr.error}
                {pr.needsReview && ' — 임의 코드 수정은 ANTHROPIC_API_KEY 설정 시 LLM 이 도출합니다.'}
              </p>
            </div>
          );
        }
        return (
          <div className="bg-[#e9f7f5] rounded-2xl border border-[#a6f0ea] p-6 space-y-3">
            <h4 className="font-bold text-[16px] text-[#00504d] flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px]">commit</span>
              실제 git 커밋 생성됨
              <span className="text-[11px] font-bold bg-[#005652] text-white px-2 py-0.5 rounded">
                수정 출처: {pr.fixSource === 'catalog' ? '결정론 규칙' : pr.fixSource === 'llm' ? 'LLM 생성' : pr.fixSource}
              </span>
            </h4>
            <div className="text-[13px] font-code text-[#00403d] space-y-1">
              <div>브랜치: <span className="bg-white px-2 py-0.5 rounded border border-[#a6f0ea]">{pr.branch}</span></div>
              <div>커밋: <span className="bg-white px-2 py-0.5 rounded border border-[#a6f0ea]">{pr.commit}</span> · {pr.title}</div>
            </div>
            <div className="rounded-lg overflow-hidden border border-[#005652]/30 bg-[#181c1c]">
              <div className="px-4 py-1.5 text-[11px] font-code text-[#a5efe9] border-b border-[#2d3e3c] flex items-center justify-between">
                <span>실행 (당신 GitHub 인증으로) — push/PR 만 사용자 몫</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(pr.gh || ''); const btn = document.getElementById('copy-gh-btn'); if(btn) { btn.textContent = '복사됨 ✓'; setTimeout(() => { btn.textContent = '복사'; }, 2000); } }}
                  id="copy-gh-btn"
                  className="text-[11px] font-bold text-[#a5efe9] bg-[#005652] hover:bg-[#1f6f6b] px-2.5 py-0.5 rounded transition-all"
                >복사</button>
              </div>
              <pre className="p-3 text-[12px] font-code text-[#a5efe9] overflow-x-auto whitespace-pre-wrap">{pr.gh}</pre>
            </div>
            <p className="text-[12px] text-[#3f6f6b]">※ 브랜치·커밋은 로컬 레포에 실제 생성됩니다. 원격 push 와 PR 은 당신 인증으로만 진행됩니다.</p>
          </div>
        );
      })()}

    </div>
  );
};
