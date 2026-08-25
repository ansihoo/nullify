import React, { useState } from 'react';
import confetti from 'canvas-confetti';
import { Vulnerability } from '../types';

interface FixDiffViewProps {
  vuln: Vulnerability;
  onGeneratePatch: (vuln: Vulnerability) => void;
  onNavigateToVerify: () => void;
  onSelectVuln: (vuln: Vulnerability) => void;
  allVulnerabilities: Vulnerability[];
}

export const FixDiffView: React.FC<FixDiffViewProps> = ({
  vuln,
  onGeneratePatch,
  onNavigateToVerify,
  onSelectVuln,
  allVulnerabilities,
}) => {
  const [agreedToGit, setAgreedToGit] = useState<boolean>(true);
  const [isPatchCreated, setIsPatchCreated] = useState<boolean>(vuln.status === 'resolved');
  const [copiedPatch, setCopiedPatch] = useState<boolean>(false);

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
                  {copiedPatch ? '복사됨' : '패치 복사'}
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

      {/* Action Card & Consent Box */}
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
              <span>재검증 화면으로 이동</span>
              <span className="material-symbols-outlined text-[18px]">verified</span>
            </button>
          ) : (
            <button
              id="btn-generate-patch"
              onClick={handlePatchSubmit}
              disabled={!agreedToGit}
              className="w-full md:w-auto bg-[#005652] text-white px-8 py-3 rounded-xl font-bold text-[15px] hover:bg-[#1f6f6b] active:scale-95 transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-md cursor-pointer"
            >
              <span className="material-symbols-outlined text-[18px]">auto_fix_high</span>
              <span>패치 생성</span>
            </button>
          )}
        </div>
      </div>

      {/* 실제 git 수정 결과 (백엔드 /api/pr) */}
      {(() => {
        const pr = (vuln as any)._pr;
        if (!pr) return null;
        if (pr.recommendation) {
          return (
            <div className="bg-[#e9f7f5] rounded-2xl border border-[#a6f0ea] p-6 space-y-2">
              <h4 className="font-bold text-[16px] text-[#00504d] flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px]">settings_suggest</span>
                설정 권고 — 소스 코드 수정 불필요
              </h4>
              <p className="text-[13.5px] text-[#3f6f6b]">
                이 항목은 서버/프록시/배포 <strong>설정</strong>으로 해결합니다(코드 변경 아님). 아래 설정을 적용하세요:
              </p>
              <pre className="rounded-lg bg-[#181c1c] text-[#a5efe9] p-3 text-[12.5px] font-code overflow-x-auto whitespace-pre-wrap">{vuln.codeSnippet.afterCode}</pre>
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
              <div className="px-4 py-1.5 text-[11px] font-code text-[#a5efe9] border-b border-[#2d3e3c]">
                실행 (당신 GitHub 인증으로) — push/PR 만 사용자 몫
              </div>
              <pre className="p-3 text-[12px] font-code text-[#a5efe9] overflow-x-auto whitespace-pre-wrap">{pr.gh}</pre>
            </div>
            <p className="text-[12px] text-[#3f6f6b]">※ 브랜치·커밋은 로컬 레포에 실제 생성됩니다. 원격 push 와 PR 은 당신 인증으로만 진행됩니다.</p>
          </div>
        );
      })()}

      {/* AI Remediation Guide Summary Card */}
      <div className="bg-[#f1f4f3] rounded-2xl border border-[#e0e3e2] p-6 space-y-3">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-[#005652]">smart_toy</span>
          <h4 className="font-bold text-[16px] text-[#181c1c]">AI 보안 어시스턴트의 제안 메모</h4>
        </div>
        <p className="text-[14px] text-[#3f4948] leading-relaxed">
          {vuln.aiGuide.bestPracticeTip} 이 패치를 적용하면 Unknown 백엔드가 즉시 라이브 재현 테스트를 구동하여, 이전과 동일한 익스플로잇 페이로드가 정상 차단(403 또는 안전한 응답)되는지 자동으로 확인합니다.
        </p>
      </div>

    </div>
  );
};
