import React, { useEffect, useState } from 'react';

interface ScanningViewProps {
  repoUrl: string;
  onScanComplete: () => void;
}

export const ScanningView: React.FC<ScanningViewProps> = ({ repoUrl, onScanComplete }) => {
  const [currentStep, setCurrentStep] = useState<number>(1); // 1 = SAST done, DAST in progress

  useEffect(() => {
    // Step progression
    const timer1 = setTimeout(() => {
      setCurrentStep(2); // DAST completed, Collecting candidates
    }, 1400);

    const timer2 = setTimeout(() => {
      setCurrentStep(3); // Exploit simulation & false-positive filtering
    }, 2800);

    const timer3 = setTimeout(() => {
      onScanComplete();
    }, 4200);

    return () => {
      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
    };
  }, [onScanComplete]);

  return (
    <div id="scanning-view-container" className="flex flex-col min-h-[calc(100vh-64px)] justify-between">
      {/* Main Center Area */}
      <main className="flex-grow flex flex-col items-center justify-center px-6 py-12">
        <div className="max-w-md w-full flex flex-col items-center space-y-8">
          
          {/* Animated Spinner and Header */}
          <div className="text-center space-y-5">
            <div className="loading-ring mx-auto">
              <div></div>
              <div></div>
              <div></div>
              <div></div>
            </div>
            <h1 className="text-[28px] sm:text-[32px] font-bold text-[#181c1c] tracking-tight">
              저장소를 분석하고 있습니다…
            </h1>
            <p className="text-[13px] font-code text-[#6f7978] bg-[#eceeed] px-3 py-1 rounded-full inline-block truncate max-w-sm">
              {repoUrl}
            </p>
          </div>

          {/* Analysis Steps Checklist Card */}
          <div className="w-full bg-white border border-[#e0e3e2] rounded-xl p-5 shadow-[0_4px_12px_rgba(0,0,0,0.03)] space-y-4">
            
            {/* Step 1: SAST */}
            <div className="flex items-center space-x-3">
              <div className="w-6 h-6 rounded-full bg-[#a6f0ea] flex items-center justify-center text-[#00504d] shrink-0">
                <span className="material-symbols-outlined text-[16px] font-bold">check</span>
              </div>
              <span className="text-[14px] text-[#6f7978]">정적 분석(SAST) 완료</span>
            </div>

            {/* Divider */}
            <div className="ml-3 w-[2px] h-4 bg-[#e0e3e2]"></div>

            {/* Step 2: DAST */}
            <div className="flex items-center space-x-3">
              {currentStep >= 2 ? (
                <div className="w-6 h-6 rounded-full bg-[#a6f0ea] flex items-center justify-center text-[#00504d] shrink-0">
                  <span className="material-symbols-outlined text-[16px] font-bold">check</span>
                </div>
              ) : (
                <div className="w-6 h-6 rounded-full border-2 border-[#1f6f6b] flex items-center justify-center shrink-0">
                  <div className="w-2 h-2 rounded-full bg-[#1f6f6b] pulse-dot"></div>
                </div>
              )}
              <span className={`text-[14px] ${currentStep >= 2 ? 'text-[#6f7978]' : 'text-[#181c1c] font-medium'}`}>
                동적 분석(DAST) {currentStep >= 2 ? '완료' : '진행중'}
              </span>
            </div>

            {/* Divider */}
            <div className="ml-3 w-[2px] h-4 bg-[#e0e3e2]"></div>

            {/* Step 3: Candidate Collection & Exploit Proof */}
            <div className="flex items-center space-x-3">
              {currentStep >= 3 ? (
                <div className="w-6 h-6 rounded-full bg-[#a6f0ea] flex items-center justify-center text-[#00504d] shrink-0">
                  <span className="material-symbols-outlined text-[16px] font-bold">check</span>
                </div>
              ) : currentStep === 2 ? (
                <div className="w-6 h-6 rounded-full border-2 border-[#1f6f6b] flex items-center justify-center shrink-0">
                  <div className="w-2 h-2 rounded-full bg-[#1f6f6b] pulse-dot"></div>
                </div>
              ) : (
                <div className="w-6 h-6 rounded-full border-2 border-[#bec9c7] flex items-center justify-center shrink-0"></div>
              )}
              <span className={`text-[14px] ${currentStep >= 3 ? 'text-[#6f7978]' : currentStep === 2 ? 'text-[#181c1c] font-medium' : 'text-[#bec9c7]'}`}>
                {currentStep >= 3 ? '익스플로잇 증명 및 노이즈 필터링 완료' : '취약점 후보 수집 대기'}
              </span>
            </div>

          </div>

          {/* Contextual Bottom Text */}
          <div className="text-center space-y-2">
            <p className="text-[14px] text-[#6f7978]">
              실제로 터지는 것만 골라내는 중 — 잠시만요.
            </p>
          </div>

        </div>
      </main>

      {/* Footer */}
      <footer className="bg-[#f7faf9] border-t border-[#e0e3e2]/50 w-full">
        <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 py-6 flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="text-[20px] font-bold text-[#005652]">
            VibeShield
          </div>
          <div className="flex space-x-6">
            <a href="#terms" onClick={(e) => e.preventDefault()} className="text-[14px] text-[#3c475a] hover:text-[#005652] transition-colors">
              이용약관
            </a>
            <a href="#privacy" onClick={(e) => e.preventDefault()} className="text-[14px] text-[#3c475a] hover:text-[#005652] transition-colors">
              개인정보처리방침
            </a>
            <a href="#contact" onClick={(e) => e.preventDefault()} className="text-[14px] text-[#3c475a] hover:text-[#005652] transition-colors">
              문의하기
            </a>
          </div>
          <div className="text-[14px] text-[#545f72]">
            © 2024 VibeShield Security. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
};
