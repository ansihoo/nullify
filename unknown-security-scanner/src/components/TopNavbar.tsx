import React from 'react';

interface TopNavbarProps {
  currentTab: 'landing' | 'scanning' | 'analysis' | 'fix' | 'verify';
  onNavigateTab?: (tab: 'analysis' | 'fix' | 'verify') => void;
  onOpenHistory?: () => void;
  onOpenSettings?: () => void;
  onConnectClick?: () => void;
  onNewScan?: () => void;
  repoUrl?: string;
  canFix?: boolean;   // 소스 레포 있음 → 수정/검증 단계 노출
  variant?: 'public' | 'workspace';   // App 이 크롬 표시를 직접 제어
}

export const TopNavbar: React.FC<TopNavbarProps> = ({
  currentTab,
  onNavigateTab,
  onOpenHistory,
  onOpenSettings,
  onConnectClick,
  onNewScan,
  repoUrl,
  canFix = false,
  variant,
}) => {
  const isPublicLanding = variant ? variant === 'public' : (currentTab === 'landing' || currentTab === 'scanning');

  if (isPublicLanding) {
    return (
      <nav id="top-navbar-public" className="bg-[#f7faf9] w-full border-b border-[#e0e3e2]/40">
        <div className="flex justify-between items-center px-4 sm:px-6 py-4 w-full max-w-7xl mx-auto">
          <div 
            className="text-[24px] leading-[1.3] font-bold text-[#005652] cursor-pointer tracking-tight"
            onClick={onConnectClick}
          >
            Unknown
          </div>
          <div className="hidden md:flex gap-6 items-center">
            <a href="#features" onClick={(e) => { e.preventDefault(); onConnectClick?.(); }} className="text-[#3f4948] font-medium text-[15px] hover:text-[#005652] transition-colors duration-200">
              기능
            </a>
            <a href="#pricing" onClick={(e) => { e.preventDefault(); onConnectClick?.(); }} className="text-[#3f4948] font-medium text-[15px] hover:text-[#005652] transition-colors duration-200">
              가격
            </a>
            <a href="#docs" onClick={(e) => { e.preventDefault(); onConnectClick?.(); }} className="text-[#3f4948] font-medium text-[15px] hover:text-[#005652] transition-colors duration-200">
              문서
            </a>
            <a href="#team" onClick={(e) => { e.preventDefault(); onConnectClick?.(); }} className="text-[#3f4948] font-medium text-[15px] hover:text-[#005652] transition-colors duration-200">
              팀
            </a>
          </div>
          <button
            id="public-nav-connect-btn"
            onClick={onConnectClick}
            className="bg-[#005652] text-white px-4 py-2 rounded-lg font-medium text-[14px] hover:bg-[#1f6f6b] active:scale-95 transition-all shadow-sm flex items-center gap-1.5"
          >
            <span className="material-symbols-outlined text-[18px]">bolt</span>
            연결하기
          </button>
        </div>
      </nav>
    );
  }

  // 워크스페이스 상단 — 진행 단계(스캔→분석→수정→검증) 스텝퍼
  const steps: { key: 'scan' | 'analysis' | 'fix' | 'verify'; label: string; num: number }[] = [
    { key: 'scan', label: '스캔', num: 1 },
    { key: 'analysis', label: '분석', num: 2 },
    ...(canFix ? [
      { key: 'fix' as const, label: '수정', num: 3 },
      { key: 'verify' as const, label: '검증', num: 4 },
    ] : []),
  ];
  const activeKey = currentTab === 'scanning' ? 'scan' : currentTab;
  const activeIdx = steps.findIndex((s) => s.key === activeKey);

  const goStep = (key: 'scan' | 'analysis' | 'fix' | 'verify') => {
    if (key === 'scan') onNewScan?.();
    else onNavigateTab?.(key);
  };

  return (
    <header id="top-navbar-workspace" className="fixed top-0 right-0 left-0 md:left-64 h-16 bg-[#f7faf9] border-b border-[#bec9c7] flex justify-between items-center px-6 z-40">
      <div className="flex items-center gap-5 min-w-0">
        <h2 className="text-[18px] font-bold text-[#005652] tracking-tight flex items-center gap-2 shrink-0">
          Unknown
          {repoUrl && (
            <span className="hidden lg:inline-block font-code text-[12px] font-normal text-[#545f72] bg-[#eceeed] px-2 py-0.5 rounded max-w-[280px] truncate">
              {repoUrl.replace('https://github.com/', '').replace('https://', '')}
            </span>
          )}
        </h2>

        {/* 진행 단계 스텝퍼 */}
        <nav className="hidden sm:flex items-center gap-1">
          {steps.map((s, i) => {
            const isActive = i === activeIdx;
            const isDone = activeIdx >= 0 && i < activeIdx;
            return (
              <React.Fragment key={s.key}>
                {i > 0 && <span className="material-symbols-outlined text-[16px] text-[#bec9c7]">chevron_right</span>}
                <button
                  onClick={() => goStep(s.key)}
                  className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[13px] font-semibold transition-colors ${
                    isActive ? 'bg-[#1f6f6b] text-white'
                    : isDone ? 'text-[#005652] hover:bg-[#e6efee]'
                    : 'text-[#8a938f] hover:bg-[#eceeed]'
                  }`}
                >
                  <span className={`w-[18px] h-[18px] rounded-full flex items-center justify-center text-[11px] font-bold ${
                    isActive ? 'bg-white text-[#1f6f6b]' : isDone ? 'bg-[#a6f0ea] text-[#00504d]' : 'bg-[#e0e3e2] text-[#8a938f]'
                  }`}>
                    {isDone ? '✓' : s.num}
                  </span>
                  {s.label}
                </button>
              </React.Fragment>
            );
          })}
        </nav>
      </div>

      <div className="flex items-center gap-2 shrink-0">
        <button
          id="btn-nav-settings"
          onClick={onOpenSettings}
          title="설정"
          className="p-2 text-[#3f4948] hover:text-[#005652] rounded-full hover:bg-[#eceeed] transition-colors"
        >
          <span className="material-symbols-outlined text-[20px]">settings</span>
        </button>
      </div>
    </header>
  );
};
