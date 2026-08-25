import React, { useState } from 'react';
import { Vulnerability } from '../types';

interface ReceiptModalProps {
  vuln: Vulnerability | null;
  isOpen: boolean;
  onClose: () => void;
}

export const ReceiptModal: React.FC<ReceiptModalProps> = ({
  vuln,
  isOpen,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<'comparison' | 'request'>('comparison');

  if (!isOpen || !vuln || !vuln.receipt) return null;

  const { receipt } = vuln;

  return (
    <div
      id="receipt-modal-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#181c1c]/70 backdrop-blur-sm animate-fade-in"
      onClick={onClose}
    >
      <div
        id="receipt-modal-dialog"
        onClick={(e) => e.stopPropagation()}
        className="bg-white rounded-2xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl border border-[#bec9c7] overflow-hidden"
      >
        {/* Modal Top Header */}
        <div className="bg-[#f7faf9] px-6 py-4 border-b border-[#bec9c7] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-[#005652] text-white flex items-center justify-center shadow-sm">
              <span className="material-symbols-outlined text-[20px]">receipt_long</span>
            </div>
            <div>
              <h3 className="text-[18px] font-bold text-[#181c1c]">
                익스플로잇 증명 영수증 (Before → After)
              </h3>
              <p className="text-xs text-[#6f7978] font-code">
                {receipt.timestamp} · {vuln.type} ({vuln.endpoint})
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#6f7978] hover:text-[#181c1c] p-1.5 rounded-full hover:bg-[#eceeed] transition-colors"
          >
            <span className="material-symbols-outlined text-[20px]">close</span>
          </button>
        </div>

        {/* Proof Summary Callout */}
        <div className="bg-[#a6f0ea]/30 px-6 py-3 border-b border-[#8ad3ce] text-xs sm:text-[13px] text-[#00504d] leading-relaxed flex items-start gap-2">
          <span className="material-symbols-outlined text-[18px] text-[#005652] shrink-0 mt-0.5">
            verified
          </span>
          <p>
            <strong>검증 요약:</strong> {receipt.proofSummary}
          </p>
        </div>

        {/* Inner Content Area */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          
          {/* HTTP Request Payload */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-bold text-[#181c1c]">
              <span className="flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[16px] text-[#005652]">send</span>
                발송된 자동 공격 페이로드 (Test Vector)
              </span>
              <span className="font-code text-[#005652] bg-[#a6f0ea]/40 px-2 py-0.5 rounded">
                Method: {receipt.method}
              </span>
            </div>
            <pre className="p-3.5 bg-[#181c1c] text-[#a5efe9] font-code text-xs rounded-xl overflow-x-auto border border-[#333a39]">
              <code>{receipt.payload}</code>
            </pre>
          </div>

          {/* Before vs After Responses Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            
            {/* Before Patch: Vulnerable */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-[#ba1a1a] flex items-center gap-1">
                  <span className="material-symbols-outlined text-[16px]">dangerous</span>
                  패치 전 응답 (취약점 발현)
                </span>
                <span className="text-[11px] font-bold font-code text-[#ba1a1a] bg-[#ffdad6] px-2 py-0.5 rounded">
                  HTTP {receipt.beforeResponse.status}
                </span>
              </div>
              <pre className="p-3.5 bg-[#201818] text-[#ffdad6] font-code text-xs rounded-xl overflow-x-auto border border-[#ba1a1a]/40 max-h-56 leading-relaxed">
                <code>{receipt.beforeResponse.body}</code>
              </pre>
            </div>

            {/* After Patch: Protected */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-[#005652] flex items-center gap-1">
                  <span className="material-symbols-outlined text-[16px]">security</span>
                  패치 후 재검증 응답 (안전하게 차단됨)
                </span>
                <span className="text-[11px] font-bold font-code text-[#00504d] bg-[#a6f0ea] px-2 py-0.5 rounded">
                  HTTP {receipt.afterResponse.status}
                </span>
              </div>
              <pre className="p-3.5 bg-[#162220] text-[#a5efe9] font-code text-xs rounded-xl overflow-x-auto border border-[#005652]/40 max-h-56 leading-relaxed">
                <code>{receipt.afterResponse.body}</code>
              </pre>
            </div>

          </div>

        </div>

        {/* Modal Footer */}
        <div className="bg-[#f7faf9] px-6 py-3.5 border-t border-[#bec9c7] flex justify-end">
          <button
            onClick={onClose}
            className="bg-[#005652] text-white px-5 py-2 rounded-lg font-bold text-xs hover:bg-[#1f6f6b] transition-all"
          >
            닫기
          </button>
        </div>

      </div>
    </div>
  );
};
