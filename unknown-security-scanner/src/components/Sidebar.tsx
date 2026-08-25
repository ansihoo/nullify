import React from 'react';

interface SidebarProps {
  currentTab: 'landing' | 'scanning' | 'analysis' | 'fix' | 'verify';
  onSelectTab: (tab: 'analysis' | 'fix' | 'verify') => void;
  onNewScan: () => void;
  onReconnect: () => void;
  unresolvedCount?: number;
  resolvedCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  onNewScan,
  onReconnect,
  unresolvedCount = 3,
  resolvedCount = 2,
}) => {
  return (
    <aside
      id="workspace-sidebar"
      className="h-screen w-64 fixed left-0 top-0 border-r border-[#bec9c7] bg-[#f7faf9] flex flex-col py-6 z-50 transition-all"
    >
      {/* Brand Header */}
      <div className="px-6 mb-6">
        <h1 
          onClick={onReconnect}
          className="text-[24px] font-bold text-[#005652] cursor-pointer hover:opacity-90 tracking-tight"
        >
          Unknown
        </h1>
        <p className="text-[12px] font-bold tracking-wider text-[#3f4948] uppercase mt-0.5">
          보안 워크스페이스
        </p>
      </div>

      {/* New Scan CTA Button */}
      <div className="px-4 mb-4">
        <button
          id="sidebar-new-scan-btn"
          onClick={onNewScan}
          className="w-full bg-[#005652] text-white py-2.5 px-4 rounded-lg text-[15px] font-bold flex items-center justify-center gap-2 hover:bg-[#1f6f6b] active:scale-[0.98] transition-all shadow-sm"
        >
          <span className="material-symbols-outlined text-[20px]">add</span>
          신규 스캔
        </button>
      </div>

      {/* Navigation Tabs */}
      <nav className="flex-1 px-3 space-y-1.5 overflow-y-auto">
        {/* Scan (Landing/Trigger) */}
        <button
          id="nav-tab-scan"
          onClick={onReconnect}
          className="w-full flex items-center justify-between px-4 py-3 text-[#3f4948] hover:bg-[#e6e9e7] transition-colors rounded-lg font-medium text-[15px] group text-left"
        >
          <div className="flex items-center gap-3">
            <span className="material-symbols-outlined text-[#6f7978] group-hover:text-[#005652] transition-colors">
              radar
            </span>
            <span>스캔</span>
          </div>
          <span className="text-[11px] text-[#6f7978] group-hover:text-[#005652] bg-[#eceeed] px-1.5 py-0.5 rounded font-code">
            Live
          </span>
        </button>

        {/* Analysis */}
        <button
          id="nav-tab-analysis"
          onClick={() => onSelectTab('analysis')}
          className={`w-full flex items-center justify-between px-4 py-3 rounded-lg font-medium text-[15px] transition-all text-left ${
            currentTab === 'analysis'
              ? 'bg-[#1f6f6b] text-[#a5efe9] font-bold shadow-sm'
              : 'text-[#3f4948] hover:bg-[#e6e9e7]'
          }`}
        >
          <div className="flex items-center gap-3">
            <span
              className={`material-symbols-outlined ${
                currentTab === 'analysis' ? 'filled text-[#a5efe9]' : 'text-[#6f7978]'
              }`}
            >
              analytics
            </span>
            <span>분석</span>
          </div>
          <span
            className={`text-[12px] font-bold px-2 py-0.5 rounded-full ${
              currentTab === 'analysis'
                ? 'bg-[#00201e] text-[#a5efe9]'
                : 'bg-[#ffdad6] text-[#93000a]'
            }`}
          >
            {unresolvedCount}
          </span>
        </button>

        {/* Fix */}
        <button
          id="nav-tab-fix"
          onClick={() => onSelectTab('fix')}
          className={`w-full flex items-center justify-between px-4 py-3 rounded-lg font-medium text-[15px] transition-all text-left ${
            currentTab === 'fix'
              ? 'bg-[#1f6f6b] text-[#a5efe9] font-bold shadow-sm'
              : 'text-[#3f4948] hover:bg-[#e6e9e7]'
          }`}
        >
          <div className="flex items-center gap-3">
            <span
              className={`material-symbols-outlined ${
                currentTab === 'fix' ? 'filled text-[#a5efe9]' : 'text-[#6f7978]'
              }`}
            >
              build
            </span>
            <span>수정</span>
          </div>
          <span
            className={`text-[12px] font-bold px-2 py-0.5 rounded-full ${
              currentTab === 'fix'
                ? 'bg-[#00201e] text-[#a5efe9]'
                : 'bg-[#eceeed] text-[#3f4948]'
            }`}
          >
            PR 준비
          </span>
        </button>

        {/* Verification */}
        <button
          id="nav-tab-verify"
          onClick={() => onSelectTab('verify')}
          className={`w-full flex items-center justify-between px-4 py-3 rounded-lg font-medium text-[15px] transition-all text-left ${
            currentTab === 'verify'
              ? 'bg-[#1f6f6b] text-[#a5efe9] font-bold shadow-sm'
              : 'text-[#3f4948] hover:bg-[#e6e9e7]'
          }`}
        >
          <div className="flex items-center gap-3">
            <span
              className={`material-symbols-outlined ${
                currentTab === 'verify' ? 'filled text-[#a5efe9]' : 'text-[#6f7978]'
              }`}
            >
              verified
            </span>
            <span>검증</span>
          </div>
          <span
            className={`text-[12px] font-bold px-2 py-0.5 rounded-full ${
              currentTab === 'verify'
                ? 'bg-[#00201e] text-[#a5efe9]'
                : 'bg-[#a6f0ea] text-[#00504d]'
            }`}
          >
            {resolvedCount} 완료
          </span>
        </button>
      </nav>

      {/* Footer Area with Reconnect Link and Profile */}
      <div className="px-4 mt-auto pt-4 border-t border-[#bec9c7]/60 space-y-3">
        <button
          id="sidebar-reconnect-link"
          onClick={onReconnect}
          className="flex items-center gap-2 text-[#3f4948] hover:text-[#005652] text-[13px] font-medium transition-colors w-full px-2"
        >
          <span className="material-symbols-outlined text-[16px]">link</span>
          <span>저장소 다시 연결</span>
        </button>

        <div className="flex items-center gap-3 px-3 py-2 bg-[#eceeed] rounded-lg">
          <div className="w-8 h-8 rounded-full bg-[#8ad3ce] text-[#00201e] font-bold flex items-center justify-center text-xs">
            UK
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[13px] font-bold text-[#181c1c] truncate">사용자 프로필</p>
            <p className="text-[11px] text-[#3f4948] truncate">Unknown 보안 도구</p>
          </div>
        </div>
      </div>
    </aside>
  );
};
