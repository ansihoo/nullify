import React, { useState, useEffect } from 'react';
import { Vulnerability } from '../types';

interface VerificationViewProps {
  vulnerabilities: Vulnerability[];
  onOpenReceipt: (vuln: Vulnerability) => void;
  onNavigateToAnalysis: (vuln: Vulnerability) => void;
  onAskAI: (question: string) => void;
  isAiLoading?: boolean;
  onRescan?: () => Promise<void> | void;
}

export const VerificationView: React.FC<VerificationViewProps> = ({
  vulnerabilities,
  onOpenReceipt,
  onNavigateToAnalysis,
  onAskAI,
  isAiLoading,
  onRescan,
}) => {
  const [progress, setProgress] = useState<number>(0);
  const [chatInput, setChatInput] = useState<string>('');
  const [isRetesting, setIsRetesting] = useState<boolean>(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setProgress((prev) => (prev < 100 ? Math.min(prev + 2, 100) : 100));
    }, 120);
    return () => clearInterval(timer);
  }, []);

  const handleInstantRetest = async () => {
    setIsRetesting(true);
    setProgress(0);
    try {
      // 실제 백엔드 재검증 호출(/api/rescan). 없으면 애니메이션만.
      if (onRescan) await onRescan();
    } finally {
      setIsRetesting(false);
      setProgress(100);
    }
  };

  const handleChatSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (chatInput.trim()) {
      onAskAI(chatInput.trim());
      setChatInput('');
    }
  };

  // 해결(resolved) vs 미해결로 분리 — 실제 백엔드 status 기준(하드코딩 id 제거).
  const resolvedVulns = vulnerabilities.filter((v) => v.status === 'resolved');
  const unresolvedVulns = vulnerabilities.filter((v) => v.status !== 'resolved' && v.status !== 'ignored');

  return (
    <div id="verification-view-container" className="p-6 max-w-7xl mx-auto space-y-6 pb-28">
      
      {/* Header */}
      <div>
        <h2 className="text-[24px] sm:text-[28px] font-bold text-[#181c1c] tracking-tight">
          재검증 — 다시 찔러 죽음 확인
        </h2>
        <p className="text-[14px] sm:text-[15px] text-[#3f4948]">
          패치 적용 후, 백엔드가 자동으로 반복 재스캔하며 취약점 재현 여부를 확인합니다.
        </p>
      </div>

      {/* Top Banner: Live Reproduction Passed */}
      {(() => {
        const totalV = vulnerabilities.length;
        const doneV = resolvedVulns.length;
        const blockRate = totalV > 0 ? Math.round((doneV / totalV) * 100) : 0;
        const allClear = totalV > 0 && doneV === totalV;
        return (
      <div className={`border-2 rounded-2xl p-5 sm:p-6 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${allClear ? 'bg-[#a6f0ea]/50 border-[#005652]' : 'bg-[#fdf2e9] border-[#e08a3c]'}`}>
        <div className="flex items-center gap-4">
          <div className={`w-12 h-12 rounded-xl text-white flex items-center justify-center shrink-0 shadow-md ${allClear ? 'bg-[#005652]' : 'bg-[#e08a3c]'}`}>
            <span className="material-symbols-outlined text-[28px]">{allClear ? 'verified' : 'sync'}</span>
          </div>
          <div>
            <h3 className="text-[18px] sm:text-[20px] font-bold text-[#00201e] flex items-center gap-2">
              {allClear
                ? '라이브 재현 → 이제 안 터짐 ✓'
                : `재검증 진행 중 — ${doneV}/${totalV} 해결`}
            </h3>
            <p className="text-[13.5px] text-[#00504d] mt-0.5">
              {allClear
                ? '이전 스캔에서 식별된 주요 위협 패턴이 효과적으로 차단되었습니다.'
                : `아직 ${totalV - doneV}건이 미해결 상태입니다. 패치 적용 후 재검증하세요.`}
            </p>
          </div>
        </div>
        <div className="text-right shrink-0">
          <span className={`inline-block font-code text-xs font-bold bg-white px-3 py-1.5 rounded-lg border ${allClear ? 'text-[#00504d] border-[#8ad3ce]' : 'text-[#b5651d] border-[#e0b48a]'}`}>
            Exploit Block Rate: {blockRate}%
          </span>
        </div>
      </div>
        );
      })()}

      {/* Active Rescan Progress Banner */}
      <div className="bg-white border border-[#bec9c7] rounded-2xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-bold text-[16px] text-[#181c1c]">
              남은 취약점 {unresolvedVulns.length}건 — 자동 재스캔이 진행 중입니다
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[13px] font-code text-[#6f7978] bg-[#eceeed] px-2.5 py-1 rounded-md">
              재검증 진행률 {Math.round(progress)}%
            </span>
            <button
              id="btn-instant-retest"
              onClick={handleInstantRetest}
              disabled={isRetesting}
              className="text-xs font-bold text-white bg-[#005652] hover:bg-[#1f6f6b] px-3 py-1.5 rounded-md transition-all active:scale-95 disabled:opacity-50"
            >
              {isRetesting ? '재검증 중...' : '지금 즉시 재스캔'}
            </button>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-[#eceeed] h-2 rounded-full overflow-hidden">
          <div className="h-full transition-all duration-200 ease-linear rounded-full" style={{ width: `${progress}%`, backgroundColor: progress < 40 ? '#8ad3ce' : progress < 80 ? '#1f6f6b' : '#005652' }}></div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 2 Columns: Vulnerability Status Cards */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Resolved Section */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="font-bold text-[16px] text-[#181c1c] flex items-center gap-2">
                <span className="w-2.5 h-2.5 bg-[#005652] rounded-full"></span>
                해결된 취약점 ({resolvedVulns.length})
              </h4>
              {resolvedVulns.length > 0 && (
                <span className="text-xs text-[#005652] font-semibold">
                  증명 영수증 발급됨
                </span>
              )}
            </div>

            <div className="space-y-3">
              {resolvedVulns.length === 0 && (
                <div className="text-[13px] text-[#8a938f] bg-[#f1f4f3] border border-[#e0e3e2] rounded-xl p-4">
                  아직 재검증으로 소멸이 확인된 항목이 없습니다. 수정을 적용한 뒤 재검증하면 여기에 영수증이 발급됩니다.
                </div>
              )}
              {resolvedVulns.map((vuln) => (
                <div
                  key={vuln.id}
                  id={`resolved-card-${vuln.id}`}
                  className="bg-white rounded-xl border border-[#a6f0ea] p-4 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-[#005652] transition-all"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-[16px] text-[#181c1c]">
                        {vuln.type}
                      </span>
                      <span className="text-[13px] font-code text-[#005652] bg-[#a6f0ea]/40 px-2 py-0.5 rounded">
                        {vuln.endpoint}
                      </span>
                      <span className="text-[11px] font-bold text-[#00504d] bg-[#a6f0ea] px-2 py-0.5 rounded">
                        증명 완료
                      </span>
                    </div>
                    <p className="text-[13px] text-[#3f4948]">
                      {vuln.description}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      id={`btn-open-receipt-${vuln.id}`}
                      onClick={() => onOpenReceipt(vuln)}
                      className="bg-[#f1f4f3] hover:bg-[#a6f0ea]/40 text-[#005652] border border-[#bec9c7] hover:border-[#005652] px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1 cursor-pointer"
                    >
                      <span className="material-symbols-outlined text-[15px]">receipt_long</span>
                      <span>영수증(before→after)</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Unresolved / In Queue Section */}
          <div className="space-y-3 pt-2">
            <div className="flex items-center justify-between">
              <h4 className="font-bold text-[16px] text-[#181c1c] flex items-center gap-2">
                <span className="w-2.5 h-2.5 bg-[#ba1a1a] rounded-full"></span>
                미해결 취약점 ({unresolvedVulns.length}) · 자동 재검증 대기 중
              </h4>
            </div>

            <div className="space-y-3">
              {unresolvedVulns.map((vuln) => (
                <div
                  key={vuln.id}
                  id={`unresolved-card-${vuln.id}`}
                  className="bg-white rounded-xl border border-[#bec9c7] p-4 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-[#6f7978] transition-all"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-[16px] text-[#181c1c]">
                        {vuln.type}
                      </span>
                      <span className="text-[13px] font-code text-[#753d25] bg-[#ffdacc]/40 px-2 py-0.5 rounded">
                        {vuln.endpoint}
                      </span>
                      <span className="text-[11px] font-bold text-[#753d25] bg-[#ffdacc] px-2 py-0.5 rounded">
                        자동 재스캔 큐에 포함됨
                      </span>
                    </div>
                    <p className="text-[13px] text-[#3f4948]">
                      {vuln.description}
                    </p>
                  </div>

                  <button
                    onClick={() => onNavigateToAnalysis(vuln)}
                    className="bg-[#005652] hover:bg-[#1f6f6b] text-white px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1 cursor-pointer shrink-0"
                  >
                    <span>분석 보기</span>
                    <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
                  </button>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Right Column: AI Verification Report */}
        <div className="space-y-4">
          <div className="bg-white rounded-2xl border border-[#bec9c7] p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-[#eceeed] pb-3">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[#005652]">assignment_turned_in</span>
                <h4 className="font-bold text-[16px] text-[#181c1c]">재검증 리포트</h4>
              </div>
              <span className="text-[11px] font-bold text-[#005652] bg-[#a6f0ea]/40 px-2 py-0.5 rounded">
                실시간 감사
              </span>
            </div>

            {(() => {
              // 실제 스캔 결과 기반 리포트(하드코딩 제거).
              const totalV = vulnerabilities.length;
              const doneV = resolvedVulns.length;
              const openV = unresolvedVulns.length;
              const score = totalV > 0 ? Math.round((doneV / totalV) * 100) : 0;
              const resolvedKinds = Array.from(new Set(resolvedVulns.map((v) => v.type)));
              const allClear = totalV > 0 && openV === 0;
              const summary = totalV === 0
                ? '아직 스캔 결과가 없습니다.'
                : doneV === 0
                ? `전체 ${totalV}건 중 재검증으로 소멸이 확인된 항목은 아직 없습니다. 수정을 적용한 뒤 재검증하세요.`
                : `전체 ${totalV}건 중 ${doneV}건이 재현 실패(소멸 확인)${openV > 0 ? `, ${openV}건 미해결` : ''}. 소멸 확인: ${resolvedKinds.join(', ')}.`;
              const scoreLabel = allClear ? '안전' : doneV > 0 ? '개선 중' : '조치 필요';
              return (
              <>
                <div className="space-y-3 text-[13.5px] text-[#3f4948] leading-relaxed">
                  <p><strong>VibeShield 재검증:</strong> {summary}</p>
                  <div className="bg-[#f1f4f3] p-3 rounded-xl border border-[#e0e3e2] space-y-1.5">
                    <div className="flex justify-between text-xs text-[#181c1c]">
                      <span>해결 진행도:</span>
                      <strong className="text-[#005652] font-bold">{score} / 100 ({scoreLabel})</strong>
                    </div>
                    <div className="w-full bg-[#e0e3e2] h-2 rounded-full overflow-hidden">
                      <div className="bg-[#005652] h-full rounded-full" style={{ width: `${score}%` }}></div>
                    </div>
                  </div>
                </div>
                <div className="pt-2 border-t border-[#eceeed] text-[12px] text-[#6f7978] flex items-center justify-between">
                  <span>재검증 항목: {doneV}/{totalV}</span>
                  <span className={`font-code ${allClear ? 'text-[#005652]' : 'text-[#a5680b]'}`}>
                    {allClear ? '전부 소멸 확인' : `미해결 ${openV}건`}
                  </span>
                </div>
              </>
              );
            })()}
          </div>
        </div>

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
            id="verify-ai-chat-input"
            type="text"
            value={chatInput}
            onChange={(e) => setChatInput(e.target.value)}
            placeholder="이 취약점에 대해 물어보세요... (예: 재검증 페이로드 원본은 어떻게 되나요?)"
            className="flex-1 bg-transparent border-none focus:outline-none text-[14px] text-[#181c1c] placeholder-[#6f7978]"
          />
          <button
            id="btn-send-verify-ai-chat"
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
