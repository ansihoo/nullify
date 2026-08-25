import React, { useState } from 'react';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose }) => {
  const [autoRetest, setAutoRetest] = useState(true);
  const [notifySlack, setNotifySlack] = useState(false);
  const [noiseFilterLevel, setNoiseFilterLevel] = useState('strict');

  if (!isOpen) return null;

  return (
    <div
      id="settings-modal-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#181c1c]/60 backdrop-blur-sm animate-fade-in"
      onClick={onClose}
    >
      <div
        id="settings-modal-dialog"
        onClick={(e) => e.stopPropagation()}
        className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-[#bec9c7] space-y-5"
      >
        <div className="flex items-center justify-between border-b border-[#eceeed] pb-3">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[#005652]">settings</span>
            <h3 className="font-bold text-[18px] text-[#181c1c]">스캐너 및 워크스페이스 설정</h3>
          </div>
          <button
            onClick={onClose}
            className="text-[#6f7978] hover:text-[#181c1c] p-1 rounded-full hover:bg-[#eceeed] transition-colors"
          >
            <span className="material-symbols-outlined text-[20px]">close</span>
          </button>
        </div>

        <div className="space-y-4 text-sm text-[#181c1c]">
          
          {/* Option 1: Auto Retest */}
          <div className="flex items-center justify-between p-3 bg-[#f1f4f3] rounded-xl border border-[#e0e3e2]">
            <div>
              <p className="font-bold text-xs sm:text-sm">실시간 자동 재검증(DAST Loop)</p>
              <p className="text-xs text-[#6f7978]">패치 생성 즉시 백그라운드 재현 테스트 수행</p>
            </div>
            <input
              type="checkbox"
              checked={autoRetest}
              onChange={(e) => setAutoRetest(e.target.checked)}
              className="w-5 h-5 text-[#005652] rounded border-[#bec9c7] focus:ring-[#005652] cursor-pointer"
            />
          </div>

          {/* Option 2: Noise Filter */}
          <div className="space-y-1.5">
            <label className="font-bold text-xs sm:text-sm text-[#181c1c]">
              노이즈 필터링 강도 (False-Positive Pruning)
            </label>
            <select
              value={noiseFilterLevel}
              onChange={(e) => setNoiseFilterLevel(e.target.value)}
              className="w-full bg-white border border-[#bec9c7] rounded-lg p-2.5 text-xs sm:text-sm focus:outline-none focus:border-[#005652]"
            >
              <option value="strict">엄격 (실제 터지는 것만 골라냄 - 기본값)</option>
              <option value="moderate">표준 (의심 영역 포함)</option>
              <option value="all">전체 (정적 SAST 원본 192건 모두 노출)</option>
            </select>
          </div>

          {/* Option 3: Notifications */}
          <div className="flex items-center justify-between p-3 bg-[#f1f4f3] rounded-xl border border-[#e0e3e2]">
            <div>
              <p className="font-bold text-xs sm:text-sm">Slack / Discord Webhook 알림</p>
              <p className="text-xs text-[#6f7978]">고위험 취약점 발견 및 해결 시 알림</p>
            </div>
            <input
              type="checkbox"
              checked={notifySlack}
              onChange={(e) => setNotifySlack(e.target.checked)}
              className="w-5 h-5 text-[#005652] rounded border-[#bec9c7] focus:ring-[#005652] cursor-pointer"
            />
          </div>

        </div>

        <div className="pt-2 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="bg-[#005652] text-white text-xs font-bold px-4 py-2 rounded-lg hover:bg-[#1f6f6b]"
          >
            저장 및 닫기
          </button>
        </div>
      </div>
    </div>
  );
};
