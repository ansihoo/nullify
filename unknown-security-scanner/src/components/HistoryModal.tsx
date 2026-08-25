import React from 'react';
import { ScanHistoryRecord } from '../types';

interface HistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  history: ScanHistoryRecord[];
  onSelectRecord: (record: ScanHistoryRecord) => void;
}

export const HistoryModal: React.FC<HistoryModalProps> = ({
  isOpen,
  onClose,
  history,
  onSelectRecord,
}) => {
  if (!isOpen) return null;

  return (
    <div
      id="history-modal-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#181c1c]/60 backdrop-blur-sm animate-fade-in"
      onClick={onClose}
    >
      <div
        id="history-modal-dialog"
        onClick={(e) => e.stopPropagation()}
        className="bg-white rounded-2xl max-w-2xl w-full p-6 shadow-2xl border border-[#bec9c7] space-y-5"
      >
        <div className="flex items-center justify-between border-b border-[#eceeed] pb-3">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[#005652]">history</span>
            <h3 className="font-bold text-[18px] text-[#181c1c]">스캔 히스토리 & 감사 기록</h3>
          </div>
          <button
            onClick={onClose}
            className="text-[#6f7978] hover:text-[#181c1c] p-1 rounded-full hover:bg-[#eceeed] transition-colors"
          >
            <span className="material-symbols-outlined text-[20px]">close</span>
          </button>
        </div>

        <div className="divide-y divide-[#eceeed] max-h-96 overflow-y-auto">
          {history.map((record) => (
            <div
              key={record.id}
              onClick={() => {
                onSelectRecord(record);
                onClose();
              }}
              className="py-3 px-2 flex items-center justify-between hover:bg-[#f1f4f3] rounded-lg transition-colors cursor-pointer"
            >
              <div className="space-y-1">
                <p className="font-code font-bold text-xs sm:text-sm text-[#005652] truncate max-w-sm">
                  {record.repoUrl}
                </p>
                <p className="text-[11px] text-[#6f7978]">
                  스캔 일시: {record.date}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <div className="text-right text-xs">
                  <span className="text-[#00504d] font-bold">{record.resolved}개 해결</span>
                  <span className="text-[#6f7978]"> / {record.totalFound}개 발견</span>
                </div>
                <span className="material-symbols-outlined text-[#6f7978] text-[18px]">
                  chevron_right
                </span>
              </div>
            </div>
          ))}
        </div>

        <div className="pt-2 flex justify-end">
          <button
            onClick={onClose}
            className="bg-[#005652] text-white text-xs font-bold px-4 py-2 rounded-lg hover:bg-[#1f6f6b]"
          >
            확인
          </button>
        </div>
      </div>
    </div>
  );
};
