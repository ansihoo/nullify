import React, { useState } from 'react';
import type { AppSettings } from '../App';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  settings: AppSettings;
  onSave: (next: AppSettings) => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose, settings, onSave }) => {
  // 열릴 때의 설정으로 초안(draft) 시작 → '저장 및 닫기' 때만 반영.
  const [autoRetest, setAutoRetest] = useState(settings.autoRetest);
  const [noiseFilter, setNoiseFilter] = useState<AppSettings['noiseFilter']>(settings.noiseFilter);
  const [notifySlack, setNotifySlack] = useState(false);   // #3 웹훅 — 아직 미연동(준비 중)

  if (!isOpen) return null;

  const handleSave = () => {
    onSave({ autoRetest, noiseFilter });   // 실제 연동되는 항목만 저장
    onClose();
  };

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

          {/* 1. 자동 재검증 — 검증뷰의 24h 쿨타임 자동 재검증을 켜고 끔 */}
          <div className="flex items-center justify-between p-3 bg-[#f1f4f3] rounded-xl border border-[#e0e3e2]">
            <div>
              <p className="font-bold text-xs sm:text-sm">자동 재검증 (24시간 주기)</p>
              <p className="text-xs text-[#6f7978]">쿨타임이 지나면 검증 페이지에서 자동으로 재검증을 실행</p>
            </div>
            <input
              type="checkbox"
              checked={autoRetest}
              onChange={(e) => setAutoRetest(e.target.checked)}
              className="w-5 h-5 text-[#005652] rounded border-[#bec9c7] focus:ring-[#005652] cursor-pointer"
            />
          </div>

          {/* 2. 노이즈 필터 — 분석뷰의 '걸러낸 오탐' 섹션 노출 제어 */}
          <div className="space-y-1.5">
            <label className="font-bold text-xs sm:text-sm text-[#181c1c]">
              노이즈 필터링 (걸러낸 오탐 표시)
            </label>
            <select
              value={noiseFilter}
              onChange={(e) => setNoiseFilter(e.target.value as AppSettings['noiseFilter'])}
              className="w-full bg-white border border-[#bec9c7] rounded-lg p-2.5 text-xs sm:text-sm focus:outline-none focus:border-[#005652]"
            >
              <option value="strict">엄격 — 재현되는 것만 (걸러낸 오탐 숨김, 기본값)</option>
              <option value="all">전체 — 걸러낸 오탐/노이즈도 함께 표시</option>
            </select>
          </div>

          {/* 3. 웹훅 알림 — 아직 미연동(백엔드 연동 필요) */}
          <div className="flex items-center justify-between p-3 bg-[#f1f4f3] rounded-xl border border-[#e0e3e2] opacity-70">
            <div>
              <p className="font-bold text-xs sm:text-sm flex items-center gap-1.5">
                Slack / Discord Webhook 알림
                <span className="text-[10px] font-bold text-[#8a5a00] bg-[#f7ecd6] px-1.5 py-0.5 rounded">준비 중</span>
              </p>
              <p className="text-xs text-[#6f7978]">고위험 취약점 발견·해결 시 알림 (아직 연동 전)</p>
            </div>
            <input
              type="checkbox"
              checked={notifySlack}
              onChange={(e) => setNotifySlack(e.target.checked)}
              disabled
              className="w-5 h-5 text-[#005652] rounded border-[#bec9c7] cursor-not-allowed"
            />
          </div>

        </div>

        <div className="pt-2 flex justify-end gap-2">
          <button
            onClick={handleSave}
            className="bg-[#005652] text-white text-xs font-bold px-4 py-2 rounded-lg hover:bg-[#1f6f6b]"
          >
            저장 및 닫기
          </button>
        </div>
      </div>
    </div>
  );
};
