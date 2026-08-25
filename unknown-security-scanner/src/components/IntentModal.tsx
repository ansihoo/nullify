import React from 'react';
import { Vulnerability } from '../types';

interface IntentModalProps {
  vuln: Vulnerability;
  isOpen: boolean;
  onClose: () => void;
  onConfirmIntent: (vulnId: string, isPrivate: boolean) => void;
}

export const IntentModal: React.FC<IntentModalProps> = ({
  vuln,
  isOpen,
  onClose,
  onConfirmIntent,
}) => {
  if (!isOpen) return null;

  const question = vuln.intentQuestion || {
    title: '확인이 필요해요',
    badgeText: `${vuln.endpoint} · ${vuln.type} 의심`,
    reasonText: "자동으로 확정 못 한 이유 — 이 데이터를 누가 봐도 되는지는 '당신 앱의 규칙'이라 저희가 모릅니다.",
    coreQuestion: '이 주문 내역은\n',
    highlightedPart: "'주문한 본인만'",
    yesOption: {
      label: '네, 본인만',
      outcome: '로그인 A로 만든 주문을 로그인 B로 열었더니 그대로 보였습니다. 진짜 문제 → 검증된 수정 PR 준비됨.',
    },
    noOption: {
      label: '아니요, 누구나 봐도 됨',
      outcome: '문제 아님. 목록에서 내립니다.',
    },
  };

  return (
    <div
      id="intent-modal-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#181c1c]/60 backdrop-blur-sm animate-fade-in"
      onClick={onClose}
    >
      <div
        id="intent-modal-dialog"
        onClick={(e) => e.stopPropagation()}
        className="bg-white rounded-2xl max-w-xl w-full p-6 sm:p-8 shadow-2xl border border-[#bec9c7] space-y-6 relative"
      >
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 text-[#6f7978] hover:text-[#181c1c] p-1 rounded-full hover:bg-[#eceeed] transition-colors"
        >
          <span className="material-symbols-outlined text-[20px]">close</span>
        </button>

        {/* Modal Header */}
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-[24px]">🔍</span>
            <h3 className="text-[22px] font-bold text-[#181c1c] tracking-tight">
              {question.title}
            </h3>
          </div>
          <div>
            <span className="text-[13px] font-code font-bold text-[#005652] bg-[#a6f0ea]/40 px-2.5 py-1 rounded-md">
              {question.badgeText}
            </span>
          </div>
        </div>

        {/* Context info message */}
        <div className="bg-[#f1f4f3] p-4 rounded-xl border border-[#e0e3e2] text-[14px] text-[#3f4948] leading-relaxed">
          <p className="font-medium text-[#181c1c] mb-1 flex items-center gap-1.5">
            <span className="material-symbols-outlined text-[16px] text-[#005652]">info</span>
            자동으로 확정 못 한 이유
          </p>
          <p>
            이 데이터를 누가 봐도 되는지는 <strong className="text-[#005652]">‘당신 앱의 비즈니스 규칙’</strong>이라 저희가 임의로 결정할 수 없습니다.
          </p>
        </div>

        {/* Core Question Highlight Box */}
        <div className="text-center py-4 px-3 bg-[#f7faf9] rounded-xl border border-[#bec9c7]/60">
          <p className="text-[18px] sm:text-[20px] font-bold text-[#181c1c] leading-snug">
            이 주문 내역은<br />
            <span className="text-[#ba1a1a] bg-[#ffdad6] px-2 py-0.5 rounded inline-block mt-1">
              ‘주문한 본인만’
            </span>{' '}
            봐야 하나요?
          </p>
        </div>

        {/* Choice Buttons with Consequence outcomes */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          
          {/* YES Option (True positive - Exploit confirmed) */}
          <button
            id="intent-choice-yes-btn"
            onClick={() => onConfirmIntent(vuln.id, true)}
            className="p-5 rounded-xl border-2 border-[#ba1a1a] bg-[#fff8f7] hover:bg-[#ffdad6]/30 text-left transition-all group active:scale-[0.98] flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="font-bold text-[16px] text-[#ba1a1a] flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[18px]">warning</span>
                  {question.yesOption.label}
                </span>
                <span className="text-[11px] font-bold text-white bg-[#ba1a1a] px-2 py-0.5 rounded">
                  진짜 문제
                </span>
              </div>
              <p className="text-[12.5px] text-[#545f72] leading-relaxed">
                {question.yesOption.outcome}
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[#ffdad6] text-[12px] font-bold text-[#ba1a1a] flex items-center gap-1">
              <span>수정 PR 생성하기</span>
              <span className="material-symbols-outlined text-[14px] group-hover:translate-x-1 transition-transform">
                arrow_forward
              </span>
            </div>
          </button>

          {/* NO Option (Public endpoint - False alarm) */}
          <button
            id="intent-choice-no-btn"
            onClick={() => onConfirmIntent(vuln.id, false)}
            className="p-5 rounded-xl border border-[#bec9c7] hover:border-[#6f7978] bg-white hover:bg-[#f1f4f3] text-left transition-all group active:scale-[0.98] flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="font-bold text-[16px] text-[#3f4948] flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[18px]">check_circle</span>
                  {question.noOption.label}
                </span>
                <span className="text-[11px] font-bold text-[#3f4948] bg-[#eceeed] px-2 py-0.5 rounded">
                  공개 엔드포인트
                </span>
              </div>
              <p className="text-[12.5px] text-[#6f7978] leading-relaxed">
                {question.noOption.outcome}
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[#eceeed] text-[12px] font-bold text-[#6f7978] flex items-center gap-1">
              <span>목록에서 제외</span>
              <span className="material-symbols-outlined text-[14px]">close</span>
            </div>
          </button>

        </div>

      </div>
    </div>
  );
};
