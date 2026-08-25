import React from 'react';

interface CleanResultViewProps {
  target: string;        // 스캔 대상(표시용)
  notice?: string | null;// 모드별 안내(탐지 전용/소스/완전체)
  noiseCount: number;    // 걸러낸 오탐/노이즈 수
  onNewScan: () => void;
}

// 취약점이 하나도 없을 때 보여주는 전용 화면 — '없음'을 분명히 강조.
export const CleanResultView: React.FC<CleanResultViewProps> = ({
  target,
  notice,
  noiseCount,
  onNewScan,
}) => {
  return (
    <div id="clean-result-view" className="min-h-[calc(100vh-64px)] flex items-center justify-center px-4 py-16">
      <div className="max-w-xl w-full text-center space-y-6">
        <div className="w-20 h-20 rounded-full bg-[#a6f0ea]/50 border-2 border-[#005652] flex items-center justify-center mx-auto shadow-sm">
          <span className="material-symbols-outlined text-[44px] text-[#005652]">verified_user</span>
        </div>

        <div className="space-y-2">
          <h1 className="text-[26px] sm:text-[30px] font-bold text-[#181c1c] tracking-tight">
            재현되는 취약점이 없습니다
          </h1>
          <p className="text-[15px] text-[#3f4948]">
            <span className="font-code text-[13px] bg-[#eceeed] text-[#545f72] px-2 py-0.5 rounded break-all">{target}</span>
            {' '}에서 실제로 터지는 취약점을 찾지 못했습니다.
          </p>
        </div>

        {notice && (
          <div className="bg-[#f1f4f3] border border-[#e0e3e2] rounded-xl p-4 text-[13.5px] text-[#3f5f5b] leading-relaxed text-left">
            {notice}
          </div>
        )}

        {noiseCount > 0 && (
          <div className="inline-flex items-center gap-2 text-[13px] text-[#6f7978] bg-white border border-[#bec9c7] rounded-full px-4 py-1.5">
            <span className="material-symbols-outlined text-[16px] text-[#005652]">filter_list_off</span>
            오탐/노이즈 <strong className="text-[#181c1c]">{noiseCount}건</strong>은 자동으로 걸러냈습니다
          </div>
        )}

        <div className="pt-2">
          <button
            onClick={onNewScan}
            className="inline-flex items-center gap-2 bg-[#1f6f6b] text-white px-6 py-3 rounded-xl font-semibold text-[15px] hover:bg-[#005652] active:scale-95 transition-all shadow-sm"
          >
            <span className="material-symbols-outlined text-[18px]">add</span>
            다른 대상 스캔하기
          </button>
        </div>

        <p className="text-[12px] text-[#8a938f] leading-relaxed">
          ※ "없음"은 <strong>검사한 범위 안에서</strong> 재현되지 않았다는 뜻입니다. 다른 표면(예: 소스 레포, 인증 뒤 페이지)까지 보려면 함께 입력해 다시 스캔하세요.
        </p>
      </div>
    </div>
  );
};
