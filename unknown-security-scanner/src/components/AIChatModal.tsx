import React, { useState } from 'react';
import { Vulnerability, ChatMessage } from '../types';

interface AIChatModalProps {
  isOpen: boolean;
  onClose: () => void;
  messages: ChatMessage[];
  onSendMessage: (text: string) => void;
  isLoading: boolean;
  selectedVuln?: Vulnerability;
}

export const AIChatModal: React.FC<AIChatModalProps> = ({
  isOpen,
  onClose,
  messages,
  onSendMessage,
  isLoading,
  selectedVuln,
}) => {
  const [inputText, setInputText] = useState('');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputText.trim() && !isLoading) {
      onSendMessage(inputText.trim());
      setInputText('');
    }
  };

  return (
    <div
      id="ai-chat-modal-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#181c1c]/60 backdrop-blur-sm animate-fade-in"
      onClick={onClose}
    >
      <div
        id="ai-chat-modal-dialog"
        onClick={(e) => e.stopPropagation()}
        className="bg-white rounded-2xl max-w-2xl w-full h-[600px] flex flex-col shadow-2xl border border-[#bec9c7] overflow-hidden"
      >
        {/* Header */}
        <div className="bg-[#f7faf9] px-6 py-4 border-b border-[#bec9c7] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#a6f0ea] text-[#005652] flex items-center justify-center">
              <span className="material-symbols-outlined text-[20px]">psychology</span>
            </div>
            <div>
              <h3 className="font-bold text-[16px] text-[#181c1c]">Unknown AI 보안 어시스턴트</h3>
              <p className="text-xs text-[#6f7978]">
                {selectedVuln ? `문맥: ${selectedVuln.type} (${selectedVuln.endpoint})` : '보안 취약점 Q&A'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#6f7978] hover:text-[#181c1c] p-1 rounded-full hover:bg-[#eceeed] transition-colors"
          >
            <span className="material-symbols-outlined text-[20px]">close</span>
          </button>
        </div>

        {/* Message Log */}
        <div className="flex-1 p-6 overflow-y-auto space-y-4 bg-[#fafbfb]">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
            >
              <div
                className={`max-w-[85%] rounded-2xl px-4 py-3 text-[13.5px] leading-relaxed ${
                  msg.sender === 'user'
                    ? 'bg-[#005652] text-white rounded-br-none'
                    : 'bg-white text-[#181c1c] border border-[#bec9c7] rounded-bl-none shadow-sm whitespace-pre-wrap'
                }`}
              >
                {msg.text}
              </div>
              <span className="text-[10.5px] text-[#6f7978] mt-1 px-1">
                {msg.timestamp}
              </span>
            </div>
          ))}

          {isLoading && (
            <div className="flex items-center gap-2 text-xs text-[#005652] bg-[#a6f0ea]/40 px-3 py-2 rounded-xl max-w-xs animate-pulse">
              <span className="material-symbols-outlined text-[16px] animate-spin">sync</span>
              <span>Gemini AI가 보안 답변을 작성 중입니다...</span>
            </div>
          )}
        </div>

        {/* Bottom Input Field */}
        <form
          onSubmit={handleSubmit}
          className="p-4 bg-white border-t border-[#bec9c7] flex items-center gap-2"
        >
          <input
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="질문을 입력하세요..."
            className="flex-1 bg-[#f1f4f3] rounded-full px-4 py-2 text-xs sm:text-sm text-[#181c1c] border border-[#bec9c7] focus:outline-none focus:border-[#005652]"
          />
          <button
            type="submit"
            disabled={isLoading || !inputText.trim()}
            className="bg-[#005652] text-white px-4 py-2 rounded-full text-xs font-bold hover:bg-[#1f6f6b] disabled:opacity-40 transition-all flex items-center gap-1"
          >
            <span>전송</span>
            <span className="material-symbols-outlined text-[16px]">send</span>
          </button>
        </form>
      </div>
    </div>
  );
};
