import React, { useState } from 'react';
import { Vulnerability, FilteredNoiseItem } from '../types';

interface AnalysisViewProps {
  vulnerabilities: Vulnerability[];
  filteredNoise: FilteredNoiseItem[];
  selectedVuln: Vulnerability;
  onSelectVuln: (vuln: Vulnerability) => void;
  onOpenIntentModal: (vuln: Vulnerability) => void;
  onNavigateToFix: (vuln: Vulnerability) => void;
  onAskAI: (question: string) => void;
  isAiLoading?: boolean;
  canFix?: boolean;   // 소스 레포 있음 → '수정' 제공 가능
  noiseFilter?: 'strict' | 'all';   // strict=오탐 숨김 / all=걸러낸 오탐도 표시
}

export const AnalysisView: React.FC<AnalysisViewProps> = ({
  vulnerabilities,
  filteredNoise,
  selectedVuln,
  onSelectVuln,
  onOpenIntentModal,
  onNavigateToFix,
  onAskAI,
  isAiLoading,
  canFix = false,
  noiseFilter = 'strict',
}) => {
  const [isNoiseExpanded, setIsNoiseExpanded] = useState<boolean>(false);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);
  const [chatInput, setChatInput] = useState<string>('');
  const [toggleStates, setToggleStates] = useState<Record<string, boolean>>({
    'vuln-1': true,
    'vuln-2': true,
    'vuln-3': true,
  });

  const highSeverityCount = vulnerabilities.filter((v) => v.severity === 'high' && v.status !== 'ignored').length;
  const mediumSeverityCount = vulnerabilities.filter((v) => v.severity === 'medium' && v.status !== 'ignored').length;

  const handleToggle = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setToggleStates((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopyCode = () => {
    if (selectedVuln.codeSnippet) {
      navigator.clipboard.writeText(selectedVuln.codeSnippet.afterCode);
      setCopiedCode(true);
      setTimeout(() => setCopiedCode(false), 2000);
    }
  };

  const handleChatSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (chatInput.trim()) {
      onAskAI(chatInput.trim());
      setChatInput('');
    }
  };

  return (
    <div id="analysis-view-container" className="flex flex-col xl:flex-row gap-6 p-6 pb-28 max-w-7xl mx-auto">
      
      {/* Left Column: Vulnerability List & Noise Section */}
      <div className="flex-1 space-y-6">
        
        {/* Header Title with Severity Badges */}
        <div>
          <div className="flex flex-wrap items-center gap-3 mb-1">
            <h2 className="text-[22px] sm:text-[24px] font-bold text-[#181c1c] tracking-tight">
              지금 진짜 터지는 것만 — 위험도순
            </h2>
            <div className="flex items-center gap-1.5">
              <span className="text-[12px] font-bold bg-[#ffdad6] text-[#93000a] px-2.5 py-0.5 rounded-full">
                {highSeverityCount} 높음
              </span>
              <span className="text-[12px] font-bold bg-[#ffdacc] text-[#753d25] px-2.5 py-0.5 rounded-full">
                {mediumSeverityCount} 중간
              </span>
            </div>
          </div>
          <p className="text-[14px] text-[#3f4948]">
            분석 완료. 익스플로잇 증명된 실제 취약점 목록입니다.
          </p>
        </div>

        {/* Vulnerabilities List */}
        <div className="space-y-4">
          {vulnerabilities
            .filter((v) => v.status !== 'ignored')
            .map((vuln) => {
              const isSelected = selectedVuln.id === vuln.id;
              const isEnabled = toggleStates[vuln.id] ?? true;

              return (
                <div
                  key={vuln.id}
                  id={`vuln-card-${vuln.id}`}
                  onClick={() => onSelectVuln(vuln)}
                  className={`bg-white rounded-xl p-5 border transition-all cursor-pointer relative ${
                    isSelected
                      ? 'border-[#005652] ring-2 ring-[#005652]/20 shadow-md'
                      : 'border-[#bec9c7] hover:border-[#6f7978] shadow-sm'
                  }`}
                >
                  {/* Left Red Accent Line for High Severity */}
                  {vuln.severity === 'high' && (
                    <div className="absolute left-0 top-3 bottom-3 w-1.5 bg-[#ba1a1a] rounded-r"></div>
                  )}

                  <div className="flex justify-between items-start gap-4">
                    
                    {/* Main Card Content */}
                    <div className="space-y-2 flex-1 pl-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-bold text-[18px] text-[#181c1c]">
                          {vuln.type}
                        </span>
                        <span className="text-[14px] font-code text-[#005652] bg-[#a6f0ea]/30 px-2 py-0.5 rounded">
                          {vuln.endpoint}
                        </span>
                        
                        {/* Status Badges */}
                        {vuln.status === 'unresolved' ? (
                          <span className="text-[12px] text-[#ba1a1a] font-medium flex items-center gap-1 bg-[#ffdad6]/60 px-2 py-0.5 rounded">
                            <span className="material-symbols-outlined text-[14px]">close</span>
                            미해결
                          </span>
                        ) : vuln.status === 'pending_intent' ? (
                          <span className="text-[12px] text-[#753d25] font-medium flex items-center gap-1 bg-[#ffdacc]/60 px-2 py-0.5 rounded">
                            <span className="material-symbols-outlined text-[14px]">help</span>
                            판단 보류
                          </span>
                        ) : (
                          <span className="text-[12px] text-[#00504d] font-medium flex items-center gap-1 bg-[#a6f0ea] px-2 py-0.5 rounded">
                            <span className="material-symbols-outlined text-[14px]">check</span>
                            해결됨
                          </span>
                        )}

                        {/* Intent Check Button if available */}
                        {vuln.requiresIntentConfirmation && (
                          <button
                            id={`btn-open-intent-${vuln.id}`}
                            onClick={(e) => {
                              e.stopPropagation();
                              onOpenIntentModal(vuln);
                            }}
                            className="text-[12px] font-bold text-[#753d25] bg-[#ffdacc] hover:bg-[#ffdacc]/80 px-2.5 py-0.5 rounded-full flex items-center gap-1 transition-all animate-pulse"
                          >
                            <span className="material-symbols-outlined text-[13px]">help_center</span>
                            의도 확인 필요
                          </button>
                        )}
                      </div>

                      <p className="text-[14px] text-[#3f4948] leading-relaxed">
                        {vuln.description}
                      </p>

                      {/* Quick Action links inside card */}
                      <div className="flex items-center gap-3 pt-1 text-[13px]">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            // 탐지 전용: fix 페이지로 안 가고 우측 패널에 상세만 표시.
                            if (canFix) onNavigateToFix(vuln);
                            else onSelectVuln(vuln);
                          }}
                          className="text-[#005652] font-semibold hover:underline flex items-center gap-1"
                        >
                          <span className="material-symbols-outlined text-[15px]">{canFix ? 'code' : 'visibility'}</span>
                          {canFix ? '수정 코드 보기' : '상세 보기'}
                        </button>
                        {vuln.requiresIntentConfirmation && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onOpenIntentModal(vuln);
                            }}
                            className="text-[#753d25] font-semibold hover:underline flex items-center gap-1"
                          >
                            <span className="material-symbols-outlined text-[15px]">verified_user</span>
                            규칙 검증하기
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Toggle Switch */}
                    <div
                      onClick={(e) => handleToggle(vuln.id, e)}
                      className={`w-11 h-6 flex items-center rounded-full p-1 cursor-pointer transition-colors duration-200 shrink-0 ${
                        isEnabled ? 'bg-[#005652]' : 'bg-[#bec9c7]'
                      }`}
                    >
                      <div
                        className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform duration-200 ${
                          isEnabled ? 'translate-x-5' : 'translate-x-0'
                        }`}
                      ></div>
                    </div>

                  </div>
                </div>
              );
            })}
        </div>

        {/* 걸러낸 오탐/노이즈 — 설정이 '전체(all)'일 때만 노출 */}
        {noiseFilter === 'all' && (
        <div className="bg-white rounded-xl border border-[#bec9c7] overflow-hidden">
          <button
            id="toggle-noise-accordion-btn"
            onClick={() => setIsNoiseExpanded(!isNoiseExpanded)}
            className="w-full px-5 py-4 flex items-center justify-between text-left hover:bg-[#f1f4f3] transition-colors"
          >
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[#6f7978] text-[20px]">
                filter_list_off
              </span>
              <span className="font-bold text-[15px] text-[#181c1c]">
                참고 (안 터짐/도달 불가) · {filteredNoise.length}건
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[12px] text-[#6f7978] bg-[#eceeed] px-2 py-0.5 rounded">
                노이즈 자동 제거됨
              </span>
              <span
                className={`material-symbols-outlined text-[#6f7978] transition-transform duration-200 ${
                  isNoiseExpanded ? 'rotate-180' : ''
                }`}
              >
                expand_more
              </span>
            </div>
          </button>

          {isNoiseExpanded && (
            <div className="px-5 pb-5 pt-2 border-t border-[#eceeed] space-y-3">
              <p className="text-[13px] text-[#6f7978]">
                정적 분석기(SAST)에서 보고되었으나 실제 런타임에서 호출되지 않거나 상위 게이트웨이에서 이미 방어되어 터지지 않는 항목들입니다:
              </p>
              <div className="divide-y divide-[#eceeed]">
                {filteredNoise.map((item) => (
                  <div key={item.id} className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[13px]">
                    <div className="flex items-center gap-2">
                      <span className="font-code font-bold text-[#3f4948] bg-[#eceeed] px-2 py-0.5 rounded text-xs">
                        {item.type}
                      </span>
                      <span className="font-code text-[#6f7978] truncate max-w-xs sm:max-w-sm">
                        {item.endpoint}
                      </span>
                    </div>
                    <span className="text-[#6f7978] text-xs">
                      {item.reason}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        )}

      </div>

      {/* Right Column: AI Guide Panel */}
      <div className="w-full xl:w-[440px] shrink-0">
        {vulnerabilities.length === 0 ? (
        <div className="bg-white rounded-xl p-6 border border-[#bec9c7] shadow-sm text-center text-[13px] text-[#8a938f] sticky top-24">
          표시할 취약점이 없습니다. 발견된 항목을 선택하면 여기에 상세가 표시됩니다.
        </div>
        ) : (
        <div className="bg-white rounded-xl p-6 border border-[#bec9c7] shadow-sm space-y-5 sticky top-24">

          {/* AI Guide Header */}
          <div className="flex items-center justify-between border-b border-[#eceeed] pb-3">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-[#a6f0ea] flex items-center justify-center text-[#005652]">
                <span className="material-symbols-outlined text-[18px]">lightbulb</span>
              </div>
              <h3 className="font-bold text-[16px] text-[#181c1c]">AI 가이드</h3>
            </div>
            <span className="text-[12px] font-code text-[#005652] bg-[#a6f0ea]/40 px-2 py-0.5 rounded font-medium">
              {selectedVuln.type}
            </span>
          </div>

          {/* Explanation */}
          <div className="space-y-2">
            <h4 className="text-[16px] font-bold text-[#181c1c]">
              {selectedVuln.aiGuide.title}
            </h4>
            <p className="text-[14px] text-[#3f4948] leading-relaxed">
              {selectedVuln.aiGuide.explanation}
            </p>
          </div>

          {/* 권고/수정 방향 — 탐지 전용이면 '권고'로, 아니면 '수정 방향' */}
          <div className="space-y-1.5 bg-[#f1f4f3] p-3.5 rounded-lg border border-[#e0e3e2]">
            <h5 className="text-[13px] font-bold text-[#005652] flex items-center gap-1.5">
              <span className="material-symbols-outlined text-[15px]">tips_and_updates</span>
              {canFix ? '수정 방향' : '권고'}
            </h5>
            <p className="text-[13px] text-[#3f4948] leading-relaxed">
              {selectedVuln.aiGuide.fixDirection}
            </p>
          </div>

          {/* 코드 수정 관련은 '수정 가능(canFix)'일 때만 노출 — 탐지 전용은 코드 얘기 안 함 */}
          {canFix ? (
            <>
              {selectedVuln.codeSnippet && (
                <div className="rounded-lg overflow-hidden border border-[#2b3131] bg-[#181c1c] text-white">
                  <div className="bg-[#242929] px-4 py-2 flex items-center justify-between text-xs text-[#a5efe9] border-b border-[#333a39]">
                    <span className="font-code font-medium">{selectedVuln.codeSnippet.fileName}</span>
                    <button
                      id="btn-copy-code-guide"
                      onClick={handleCopyCode}
                      className="text-xs text-[#bec9c7] hover:text-white flex items-center gap-1 transition-colors"
                    >
                      <span className="material-symbols-outlined text-[14px]">{copiedCode ? 'check' : 'content_copy'}</span>
                      {copiedCode ? '복사됨' : '복사'}
                    </button>
                  </div>
                  <div className="p-3 font-code text-[12.5px] leading-relaxed overflow-x-auto space-y-1">
                    <div className="text-[#ffb4ab] bg-[#ba1a1a]/20 px-2 py-1 rounded">
                      <span className="text-[#ffdad6]/60 select-none mr-2">1</span>
                      {selectedVuln.codeSnippet.beforeCode}
                    </div>
                    <div className="text-[#a5efe9] bg-[#005652]/40 px-2 py-1 rounded">
                      <span className="text-[#a5efe9]/60 select-none mr-2">2</span>
                      {selectedVuln.codeSnippet.afterCode}
                    </div>
                  </div>
                </div>
              )}
              <button
                id="btn-apply-code-to-fix"
                onClick={() => onNavigateToFix(selectedVuln)}
                className="w-full bg-[#005652] text-white py-3 px-4 rounded-lg font-bold text-[15px] hover:bg-[#1f6f6b] active:scale-[0.98] transition-all flex items-center justify-center gap-2 shadow-sm cursor-pointer"
              >
                <span>다음: 수정</span>
                <span className="material-symbols-outlined text-[18px]">arrow_forward</span>
              </button>
            </>
          ) : ((selectedVuln as any)._raw?.kind === 'headers') ? (
            <div className="space-y-2">
              <div className="text-[12px] text-[#3f5f5b]">
                URL만 스캔이라 자동 적용은 불가 — 쓰는 스택에 맞게 복붙하세요. (레포도 올리면 자동 커밋)
              </div>
              {[
                { l: 'Express', c: `app.use((req,res,next)=>{\n  res.setHeader('X-Frame-Options','DENY');\n  res.setHeader('Content-Security-Policy',"default-src 'self'");\n  res.setHeader('X-Content-Type-Options','nosniff');\n  next();\n});` },
                { l: '정적 (public/_headers)', c: `/*\n  X-Frame-Options: DENY\n  Content-Security-Policy: default-src 'self'\n  X-Content-Type-Options: nosniff` },
                { l: 'Nginx', c: `add_header X-Frame-Options "DENY" always;\nadd_header Content-Security-Policy "default-src 'self'" always;\nadd_header X-Content-Type-Options "nosniff" always;` },
              ].map((s) => (
                <div key={s.l}>
                  <div className="text-[11px] font-bold text-[#005652] mb-0.5">{s.l}</div>
                  <pre className="rounded-lg bg-[#181c1c] text-[#a5efe9] p-2.5 text-[11.5px] font-code overflow-x-auto whitespace-pre-wrap">{s.c}</pre>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-[#eef4f3] border border-[#cfe0dd] rounded-lg p-3.5 text-[12.5px] text-[#3f5f5b] leading-relaxed">
              <span className="material-symbols-outlined text-[15px] align-middle mr-1 text-[#1f6f6b]">travel_explore</span>
              탐지 전용 — 발견까지만 제공합니다. 검증된 <strong>코드 수정·PR</strong>을 받으려면 상단에 <strong>GitHub 레포도 함께</strong> 올려 다시 스캔하세요.
            </div>
          )}

        </div>
        )}
      </div>

      {/* Floating Bottom AI Chat Bar */}
      <div className="fixed bottom-0 right-0 left-0 md:left-64 bg-white/95 backdrop-blur border-t border-[#bec9c7] p-4 z-40">
        <form
          onSubmit={handleChatSubmit}
          className="max-w-4xl mx-auto flex items-center gap-2 bg-[#f1f4f3] rounded-full px-4 py-2 border border-[#bec9c7] focus-within:border-[#005652] focus-within:ring-2 focus-within:ring-[#005652]/20 transition-all"
        >
          <span className="material-symbols-outlined text-[#005652] text-[20px]">
            psychology
          </span>
          <input
            id="analysis-ai-chat-input"
            type="text"
            value={chatInput}
            onChange={(e) => setChatInput(e.target.value)}
            placeholder="이 취약점에 대해 물어보세요... (예: JWT 서명 검증은 어떻게 추가하나요?)"
            className="flex-1 bg-transparent border-none focus:outline-none text-[14px] text-[#181c1c] placeholder-[#6f7978]"
          />
          <button
            id="btn-send-analysis-ai-chat"
            type="submit"
            disabled={isAiLoading || !chatInput.trim()}
            className="bg-[#005652] text-white p-2 rounded-full hover:bg-[#1f6f6b] disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            <span className="material-symbols-outlined text-[18px]">
              {isAiLoading ? 'sync' : 'send'}
            </span>
          </button>
        </form>
      </div>

    </div>
  );
};
