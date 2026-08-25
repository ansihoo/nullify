import React from 'react';

// 사이드바에 뿌릴 스캔 세션 요약(대화 목록 항목).
export interface HistoryItem {
  id: string;
  label: string;      // 대상(URL/레포)에서 뽑은 표시 이름
  ts: string;         // 사람이 읽는 시각
  mode: 'detect' | 'source' | 'combined';
  total: number;
  crit: number;
  ques: number;
  warn: number;
}

interface SidebarProps {
  history: HistoryItem[];
  activeId: string | null;
  onSelectSession: (id: string) => void;
  onNewScan: () => void;
}

const MODE_BADGE: Record<HistoryItem['mode'], { text: string; cls: string }> = {
  detect:   { text: '탐지', cls: 'bg-[#e7f1fd] text-[#1a4d80]' },
  source:   { text: '소스', cls: 'bg-[#efe9fb] text-[#5a3fb0]' },
  combined: { text: '완전체', cls: 'bg-[#dcf0f3] text-[#00504d]' },
};

export const Sidebar: React.FC<SidebarProps> = ({
  history,
  activeId,
  onSelectSession,
  onNewScan,
}) => {
  return (
    <aside
      id="workspace-sidebar"
      className="h-screen w-64 fixed left-0 top-0 border-r border-[#bec9c7] bg-[#f7faf9] flex flex-col z-50"
    >
      {/* 브랜드 + 신규 스캔 */}
      <div className="px-4 py-4 border-b border-[#e0e3e2]">
        <div className="text-[20px] font-bold text-[#005652] tracking-tight mb-3">VibeShield</div>
        <button
          id="sidebar-new-scan"
          onClick={onNewScan}
          className="w-full flex items-center justify-center gap-2 bg-[#1f6f6b] text-white py-2.5 rounded-lg font-semibold text-[14px] hover:bg-[#005652] active:scale-[0.98] transition-all shadow-sm"
        >
          <span className="material-symbols-outlined text-[18px]">add</span>
          새 스캔
        </button>
      </div>

      {/* 스캔 히스토리(대화 목록) */}
      <div className="flex-1 overflow-y-auto px-2 py-3">
        <div className="px-2 mb-2 text-[11px] font-bold uppercase tracking-wider text-[#8a938f]">
          스캔 기록
        </div>
        {history.length === 0 ? (
          <div className="px-3 py-6 text-[13px] text-[#8a938f] leading-relaxed">
            아직 스캔 기록이 없습니다.<br />‘새 스캔’으로 시작하세요.
          </div>
        ) : (
          <ul className="flex flex-col gap-1">
            {history.map((h) => {
              const isActive = h.id === activeId;
              const badge = MODE_BADGE[h.mode];
              return (
                <li key={h.id}>
                  <button
                    onClick={() => onSelectSession(h.id)}
                    className={`w-full text-left px-3 py-2.5 rounded-lg transition-colors group ${
                      isActive ? 'bg-[#e6efee] border border-[#a6d5d0]' : 'hover:bg-[#eceeed] border border-transparent'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className={`font-code text-[12.5px] truncate ${isActive ? 'text-[#00403d] font-semibold' : 'text-[#3f4948]'}`}>
                        {h.label}
                      </span>
                      <span className={`shrink-0 text-[10px] font-bold px-1.5 py-0.5 rounded ${badge.cls}`}>
                        {badge.text}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-[11px] text-[#8a938f]">
                      <span>{h.ts}</span>
                      {h.crit > 0 && <span className="text-[#c0392b] font-semibold">진짜 {h.crit}</span>}
                      {h.ques > 0 && <span className="text-[#6a4bd0] font-semibold">질문 {h.ques}</span>}
                      {h.warn > 0 && <span className="text-[#a5680b] font-semibold">경고 {h.warn}</span>}
                      {h.crit === 0 && h.ques === 0 && h.warn === 0 && <span>이슈 없음</span>}
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      <div className="px-4 py-3 border-t border-[#e0e3e2] text-[11px] text-[#8a938f]">
        결정론 검증 보안 스캐너
      </div>
    </aside>
  );
};
