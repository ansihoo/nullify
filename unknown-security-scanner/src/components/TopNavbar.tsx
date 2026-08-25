import React from 'react';

interface TopNavbarProps {
  currentTab: 'landing' | 'scanning' | 'analysis' | 'fix' | 'verify';
  onNavigateTab?: (tab: 'analysis' | 'fix' | 'verify') => void;
  onOpenHistory?: () => void;
  onOpenSettings?: () => void;
  onConnectClick?: () => void;
  repoUrl?: string;
}

export const TopNavbar: React.FC<TopNavbarProps> = ({
  currentTab,
  onNavigateTab,
  onOpenHistory,
  onOpenSettings,
  onConnectClick,
  repoUrl,
}) => {
  const isPublicLanding = currentTab === 'landing' || currentTab === 'scanning';

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

  // Dashboard / Workspace Top Header
  return (
    <header id="top-navbar-workspace" className="fixed top-0 right-0 left-0 md:left-64 h-16 bg-[#f7faf9] border-b border-[#bec9c7] flex justify-between items-center px-6 z-40">
      <div className="flex items-center gap-6">
        <h2 className="text-[20px] font-bold text-[#005652] tracking-tight flex items-center gap-2">
          Unknown Scanner
          {repoUrl && (
            <span className="hidden lg:inline-block font-code text-[12px] font-normal text-[#545f72] bg-[#eceeed] px-2 py-0.5 rounded max-w-xs truncate">
              {repoUrl.replace('https://github.com/', '')}
            </span>
          )}
        </h2>
        <nav className="hidden sm:flex items-center gap-1">
          <button
            onClick={() => onNavigateTab?.('analysis')}
            className={`px-3 py-1.5 rounded-md text-[13px] font-bold tracking-wider transition-colors ${
              currentTab === 'analysis'
                ? 'text-[#005652] bg-[#a6f0ea]/40 font-semibold'
                : 'text-[#3f4948] hover:text-[#181c1c] hover:bg-[#eceeed]'
            }`}
          >
            대시보드
          </button>
          <button
            onClick={onOpenHistory}
            className="px-3 py-1.5 rounded-md text-[13px] font-bold tracking-wider text-[#3f4948] hover:text-[#181c1c] hover:bg-[#eceeed] transition-colors"
          >
            히스토리
          </button>
          <button
            onClick={onOpenSettings}
            className="px-3 py-1.5 rounded-md text-[13px] font-bold tracking-wider text-[#3f4948] hover:text-[#181c1c] hover:bg-[#eceeed] transition-colors"
          >
            설정
          </button>
        </nav>
      </div>

      <div className="flex items-center gap-3">
        <button
          id="btn-nav-notifications"
          onClick={onOpenHistory}
          title="스캔 알림"
          className="p-2 text-[#3f4948] hover:text-[#005652] rounded-full hover:bg-[#eceeed] transition-colors relative"
        >
          <span className="material-symbols-outlined text-[20px]">notifications</span>
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-[#ba1a1a] rounded-full"></span>
        </button>
        <button
          id="btn-nav-settings"
          onClick={onOpenSettings}
          title="설정"
          className="p-2 text-[#3f4948] hover:text-[#005652] rounded-full hover:bg-[#eceeed] transition-colors"
        >
          <span className="material-symbols-outlined text-[20px]">settings</span>
        </button>
        <div 
          onClick={onOpenSettings}
          className="w-8 h-8 rounded-full bg-[#d5e0f7] border border-[#bec9c7] overflow-hidden cursor-pointer hover:ring-2 hover:ring-[#005652] transition-all flex items-center justify-center"
          title="보안 관리자"
        >
          <img
            src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80"
            alt="User Avatar"
            className="w-full h-full object-cover"
            referrerPolicy="no-referrer"
          />
        </div>
      </div>
    </header>
  );
};
