import React, { useState } from 'react';

interface LandingViewProps {
  onStartScan: (url: string, repo: string) => void;
}

export const LandingView: React.FC<LandingViewProps> = ({ onStartScan }) => {
  const [inputUrl, setInputUrl] = useState('');    // 사이트 URL (DAST 대상)
  const [inputRepo, setInputRepo] = useState('');  // GitHub 레포 (SAST + 수정)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const url = inputUrl.trim();
    const repo = inputRepo.trim();
    if (!url && !repo) {
      // 둘 다 비면 로컬 데모 과녁으로(탐지 전용).
      onStartScan('http://127.0.0.1:8009', '');
      return;
    }
    onStartScan(url, repo);
  };

  const handleSelectSample = (sampleUrl: string) => {
    setInputRepo(sampleUrl);
    onStartScan('', sampleUrl);
  };

  return (
    <div id="landing-view-container" className="flex flex-col min-h-[calc(100vh-64px)] justify-between">
      {/* Main Hero Section */}
      <main className="flex-grow flex flex-col items-center justify-center px-4 py-16 w-full max-w-7xl mx-auto">
        <div className="text-center mb-10 w-full max-w-3xl animate-fade-in">
          <h1 className="text-[32px] sm:text-[38px] font-bold text-[#1f6f6b] mb-4 tracking-tight">
            VibeShield
          </h1>
          <p className="text-[20px] sm:text-[22px] text-[#3f4948] font-normal leading-relaxed">
            지금 당신 앱에서 진짜 터지는 것만 골라, 고치고, 증명합니다.
          </p>
        </div>

        {/* Input Card Container */}
        <div className="w-full max-w-2xl flex flex-col items-center">
          <form
            onSubmit={handleSubmit}
            className="w-full bg-white border border-[#bec9c7] rounded-xl p-3 flex flex-col gap-2 custom-shadow focus-shadow transition-all duration-300"
          >
            {/* 사이트 URL — DAST(런타임 탐지) */}
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[#6f7978] ml-1 text-[20px] select-none">public</span>
              <input
                id="landing-repo-input"
                type="text"
                value={inputUrl}
                onChange={(e) => setInputUrl(e.target.value)}
                placeholder="사이트 URL (실행 중인 앱을 찔러 탐지)"
                className="flex-grow border-none focus:outline-none focus:ring-0 bg-transparent text-[15px] placeholder-[#bec9c7] text-[#181c1c] font-code px-1 py-1.5"
              />
            </div>
            <div className="h-px bg-[#e0e3e2]"></div>
            {/* GitHub 레포 — SAST + 실제 코드 수정 */}
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[#6f7978] ml-1 text-[20px] select-none">folder_code</span>
              <input
                id="landing-repo-input-git"
                type="text"
                value={inputRepo}
                onChange={(e) => setInputRepo(e.target.value)}
                placeholder="GitHub 레포 (선택 — 있으면 검증된 수정/PR 생성)"
                className="flex-grow border-none focus:outline-none focus:ring-0 bg-transparent text-[15px] placeholder-[#bec9c7] text-[#181c1c] font-code px-1 py-1.5"
              />
              <button
                id="landing-submit-btn"
                type="submit"
                className="bg-[#1f6f6b] text-white px-6 py-2.5 rounded-lg font-medium text-[15px] whitespace-nowrap hover:bg-[#005652] active:scale-95 transition-all flex items-center gap-2 shadow-sm cursor-pointer"
              >
                <span>연결하기</span>
                <span className="material-symbols-outlined text-[18px]">arrow_forward</span>
              </button>
            </div>
          </form>

          <p className="text-[13px] text-[#6f7978] mt-3">
            URL만 = <strong>탐지 전용</strong> · 레포까지 = <strong>검증된 수정</strong>까지 · 둘 다 = 완전체(런타임 증거+소스)
          </p>

          {/* Quick Demo Repositories */}
          <div className="mt-8 flex flex-wrap items-center justify-center gap-2 text-center">
            <span className="text-[12px] text-[#6f7978] font-medium mr-1">빠른 테스트 샘플:</span>
            <button
              onClick={() => handleSelectSample('https://github.com/my-org/express-commerce-api')}
              className="text-[12px] font-code bg-[#eceeed] hover:bg-[#d8dbd9] text-[#1f6f6b] px-2.5 py-1 rounded-md transition-colors border border-[#bec9c7]/50"
            >
              express-commerce-api
            </button>
            <button
              onClick={() => handleSelectSample('https://github.com/acme-corp/user-order-service')}
              className="text-[12px] font-code bg-[#eceeed] hover:bg-[#d8dbd9] text-[#1f6f6b] px-2.5 py-1 rounded-md transition-colors border border-[#bec9c7]/50"
            >
              user-order-service
            </button>
            <button
              onClick={() => handleSelectSample('https://github.com/startup/fintech-payment-core')}
              className="text-[12px] font-code bg-[#eceeed] hover:bg-[#d8dbd9] text-[#1f6f6b] px-2.5 py-1 rounded-md transition-colors border border-[#bec9c7]/50"
            >
              fintech-payment-core
            </button>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer id="landing-footer" className="bg-[#f7faf9] w-full border-t border-[#e0e3e2] mt-auto">
        <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 py-8 flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="text-[20px] font-bold text-[#005652]">
            VibeShield
          </div>
          <div className="flex gap-6 items-center">
            <a href="#terms" onClick={(e) => e.preventDefault()} className="text-[#3c475a] text-[14px] hover:text-[#005652] transition-colors">
              이용약관
            </a>
            <a href="#privacy" onClick={(e) => e.preventDefault()} className="text-[#3c475a] text-[14px] hover:text-[#005652] transition-colors">
              개인정보처리방침
            </a>
            <a href="#contact" onClick={(e) => e.preventDefault()} className="text-[#3c475a] text-[14px] hover:text-[#005652] transition-colors">
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
