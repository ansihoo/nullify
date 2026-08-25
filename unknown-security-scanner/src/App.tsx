import React, { useState, useRef } from 'react';
import { TopNavbar } from './components/TopNavbar';
import { Sidebar } from './components/Sidebar';
import { LandingView } from './components/LandingView';
import { ScanningView } from './components/ScanningView';
import { AnalysisView } from './components/AnalysisView';
import { FixDiffView } from './components/FixDiffView';
import { VerificationView } from './components/VerificationView';
import { IntentModal } from './components/IntentModal';
import { ReceiptModal } from './components/ReceiptModal';
import { HistoryModal } from './components/HistoryModal';
import { SettingsModal } from './components/SettingsModal';
import { AIChatModal } from './components/AIChatModal';
import {
  INITIAL_VULNERABILITIES,
  SAMPLE_FILTERED_NOISE,
  INITIAL_SCAN_HISTORY,
} from './data/mockSecurityData';
import { Vulnerability, ChatMessage, ScanHistoryRecord } from './types';
import { scanTarget } from './api/nullify';

export function App() {
  const [currentTab, setCurrentTab] = useState<'landing' | 'scanning' | 'analysis' | 'fix' | 'verify'>('landing');
  // 백엔드는 로컬 전용(127.0.0.1) + 공개 URL 거부이므로 기본 대상은 데모 과녁 앱.
  const [repoUrl, setRepoUrl] = useState<string>('http://127.0.0.1:8009');
  const [scanError, setScanError] = useState<string | null>(null);
  const scanningRef = useRef<boolean>(false);   // 실제 스캔 진행중? (애니메이션과 경합 방지)
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>(INITIAL_VULNERABILITIES);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability>(INITIAL_VULNERABILITIES[0]);
  const [filteredNoise, setFilteredNoise] = useState(SAMPLE_FILTERED_NOISE);
  const [scanHistory, setScanHistory] = useState<ScanHistoryRecord[]>(INITIAL_SCAN_HISTORY);

  // Modals state
  const [isIntentModalOpen, setIsIntentModalOpen] = useState<boolean>(false);
  const [intentTargetVuln, setIntentTargetVuln] = useState<Vulnerability | null>(null);

  const [isReceiptModalOpen, setIsReceiptModalOpen] = useState<boolean>(false);
  const [receiptTargetVuln, setReceiptTargetVuln] = useState<Vulnerability | null>(null);

  const [isHistoryModalOpen, setIsHistoryModalOpen] = useState<boolean>(false);
  const [isSettingsModalOpen, setIsSettingsModalOpen] = useState<boolean>(false);
  const [isAIChatModalOpen, setIsAIChatModalOpen] = useState<boolean>(false);

  // AI Chat state
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      id: 'msg-1',
      sender: 'ai',
      text: '안녕하세요! Unknown 보안 어시스턴트입니다. 발견된 취약점의 실제 익스플로잇 가능성이나 코드 패치 방향에 대해 궁금한 점을 질문해 주세요.',
      timestamp: '방금 전',
    },
  ]);
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);

  // Handlers
  const handleStartScan = async (targetUrl: string) => {
    setRepoUrl(targetUrl);
    setScanError(null);
    setCurrentTab('scanning');
    scanningRef.current = true;
    try {
      // 실제 백엔드 결정론 스캔 호출 (mock 대체). discover=1 로 임의 앱 후보 자동발견.
      const { vulnerabilities: vulns, filteredNoise: noise } = await scanTarget(targetUrl);
      setVulnerabilities(vulns);
      setFilteredNoise(noise);
      if (vulns.length) setSelectedVuln(vulns[0]);
    } catch (e: any) {
      setScanError(e?.message || String(e));
      setVulnerabilities([]);
      setFilteredNoise([]);
    } finally {
      scanningRef.current = false;
      setCurrentTab('analysis');   // 스캔이 끝나면(성공/실패) 결과 화면으로.
    }
  };

  // ScanningView 애니메이션(약 4.2초)이 먼저 끝난 경우: 스캔이 아직 진행중이면
  // 넘기지 않고, 위 handleStartScan 의 finally 가 넘기도록 둔다(경합 방지).
  const handleScanComplete = () => {
    if (!scanningRef.current) setCurrentTab('analysis');
  };

  const handleSelectVuln = (vuln: Vulnerability) => {
    setSelectedVuln(vuln);
  };

  const handleOpenIntentModal = (vuln: Vulnerability) => {
    setIntentTargetVuln(vuln);
    setIsIntentModalOpen(true);
  };

  const handleConfirmIntent = (vulnId: string, isPrivate: boolean) => {
    if (isPrivate) {
      // User confirmed it is strictly private -> Confirmed True Positive Exploit
      setVulnerabilities((prev) =>
        prev.map((v) =>
          v.id === vulnId
            ? {
                ...v,
                requiresIntentConfirmation: false,
                statusText: '미해결 (확정)',
                description: '주문한 본인만 열람 가능한 데이터이나 타 사용자의 무단 접근이 입증되었습니다.',
              }
            : v
        )
      );
      setIsIntentModalOpen(false);
      // Auto navigate to fix view for convenience
      const updatedVuln = vulnerabilities.find((v) => v.id === vulnId);
      if (updatedVuln) {
        setSelectedVuln(updatedVuln);
        setCurrentTab('fix');
      }
    } else {
      // User said anyone can view it -> Mark as ignored / false positive
      setVulnerabilities((prev) =>
        prev.map((v) =>
          v.id === vulnId
            ? {
                ...v,
                status: 'ignored',
                statusText: '공개 정책 확인됨',
                requiresIntentConfirmation: false,
              }
            : v
        )
      );
      setFilteredNoise((prev) => [
        {
          id: `noise-${Date.now()}`,
          type: 'Public Data Endpoint',
          endpoint: intentTargetVuln?.endpoint || '/orders/1024',
          reason: '사용자 의도 확인 완료: 누구나 접근 가능한 공개 리소스로 판명되어 목록에서 제외됨',
          category: 'false_positive',
        },
        ...prev,
      ]);
      setIsIntentModalOpen(false);
    }
  };

  const handleNavigateToFix = (vuln: Vulnerability) => {
    setSelectedVuln(vuln);
    setCurrentTab('fix');
  };

  const handleGeneratePatch = (vuln: Vulnerability) => {
    setVulnerabilities((prev) =>
      prev.map((v) =>
        v.id === vuln.id
          ? {
              ...v,
              status: 'resolved',
              statusText: '수정 완료',
            }
          : v
      )
    );
  };

  const handleNavigateToVerify = () => {
    setCurrentTab('verify');
  };

  const handleOpenReceipt = (vuln: Vulnerability) => {
    setReceiptTargetVuln(vuln);
    setIsReceiptModalOpen(true);
  };

  const handleAskAI = async (question: string) => {
    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: question,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setChatMessages((prev) => [...prev, userMsg]);
    setIsAIChatModalOpen(true);
    setIsAiLoading(true);

    try {
      const response = await fetch('/api/gemini/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: question,
          vulnContext: selectedVuln,
        }),
      });

      if (!response.ok) {
        throw new Error('API 응답 에러');
      }

      const data = await response.json();
      const aiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        sender: 'ai',
        text: data.reply || '답변을 생성할 수 없습니다.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setChatMessages((prev) => [...prev, aiMsg]);
    } catch (err: any) {
      console.error('AI chat failed:', err);
      const errorAiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        sender: 'ai',
        text: `[Unknown AI 보안 응답]\n${selectedVuln.type} (${selectedVuln.endpoint}) 취약점의 경우, ${selectedVuln.aiGuide.fixDirection} 원칙을 준수하여 패치를 적용하면 안전하게 보호됩니다.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setChatMessages((prev) => [...prev, errorAiMsg]);
    } finally {
      setIsAiLoading(false);
    }
  };

  const handleSelectHistoryRecord = (record: ScanHistoryRecord) => {
    setRepoUrl(record.repoUrl);
    setCurrentTab('analysis');
  };

  const unresolvedCount = vulnerabilities.filter((v) => v.status !== 'resolved' && v.status !== 'ignored').length;
  const resolvedCount = vulnerabilities.filter((v) => v.status === 'resolved' || v.id === 'vuln-1' || v.id === 'vuln-2').length;

  return (
    <div className="min-h-screen bg-[#f7faf9] text-[#181c1c] flex flex-col font-sans selection:bg-[#a6f0ea] selection:text-[#00201e]">
      
      {/* Top Navbar */}
      <TopNavbar
        currentTab={currentTab}
        onNavigateTab={(tab) => setCurrentTab(tab)}
        onOpenHistory={() => setIsHistoryModalOpen(true)}
        onOpenSettings={() => setIsSettingsModalOpen(true)}
        onConnectClick={() => setCurrentTab('landing')}
        repoUrl={repoUrl}
      />

      {/* 스캔 오류 배너 (백엔드 미기동/권한거부/인증 등) */}
      {scanError && (
        <div className="bg-[#fdecea] border-b border-[#f5c6c0] text-[#a11c10] px-4 py-2 text-[13px] text-center">
          스캔 실패: {scanError}
          <span className="text-[#7a1409]"> — 백엔드가 켜져 있는지(python web.py), 대상이 로컬/사설망인지 확인하세요.</span>
        </div>
      )}

      {/* Main Workspace Layout with Conditional Sidebar */}
      <div className="flex-1 flex w-full">
        {currentTab !== 'landing' && currentTab !== 'scanning' && (
          <Sidebar
            currentTab={currentTab}
            onSelectTab={(tab) => setCurrentTab(tab)}
            onNewScan={() => setCurrentTab('landing')}
            onReconnect={() => setCurrentTab('landing')}
            unresolvedCount={unresolvedCount}
            resolvedCount={resolvedCount}
          />
        )}

        <main
          className={`flex-1 transition-all ${
            currentTab !== 'landing' && currentTab !== 'scanning'
              ? 'md:ml-64 pt-16'
              : ''
          }`}
        >
          {currentTab === 'landing' && (
            <LandingView onStartScan={handleStartScan} />
          )}

          {currentTab === 'scanning' && (
            <ScanningView
              repoUrl={repoUrl}
              onScanComplete={handleScanComplete}
            />
          )}

          {currentTab === 'analysis' && (
            <AnalysisView
              vulnerabilities={vulnerabilities}
              filteredNoise={filteredNoise}
              selectedVuln={selectedVuln}
              onSelectVuln={handleSelectVuln}
              onOpenIntentModal={handleOpenIntentModal}
              onNavigateToFix={handleNavigateToFix}
              onAskAI={handleAskAI}
              isAiLoading={isAiLoading}
            />
          )}

          {currentTab === 'fix' && (
            <FixDiffView
              vuln={selectedVuln}
              onGeneratePatch={handleGeneratePatch}
              onNavigateToVerify={handleNavigateToVerify}
              onSelectVuln={handleSelectVuln}
              allVulnerabilities={vulnerabilities}
            />
          )}

          {currentTab === 'verify' && (
            <VerificationView
              vulnerabilities={vulnerabilities}
              onOpenReceipt={handleOpenReceipt}
              onNavigateToAnalysis={handleNavigateToFix}
              onAskAI={handleAskAI}
              isAiLoading={isAiLoading}
            />
          )}
        </main>
      </div>

      {/* Modals & Dialogs */}
      {isIntentModalOpen && intentTargetVuln && (
        <IntentModal
          vuln={intentTargetVuln}
          isOpen={isIntentModalOpen}
          onClose={() => setIsIntentModalOpen(false)}
          onConfirmIntent={handleConfirmIntent}
        />
      )}

      {isReceiptModalOpen && receiptTargetVuln && (
        <ReceiptModal
          vuln={receiptTargetVuln}
          isOpen={isReceiptModalOpen}
          onClose={() => setIsReceiptModalOpen(false)}
        />
      )}

      {isHistoryModalOpen && (
        <HistoryModal
          isOpen={isHistoryModalOpen}
          onClose={() => setIsHistoryModalOpen(false)}
          history={scanHistory}
          onSelectRecord={handleSelectHistoryRecord}
        />
      )}

      {isSettingsModalOpen && (
        <SettingsModal
          isOpen={isSettingsModalOpen}
          onClose={() => setIsSettingsModalOpen(false)}
        />
      )}

      {isAIChatModalOpen && (
        <AIChatModal
          isOpen={isAIChatModalOpen}
          onClose={() => setIsAIChatModalOpen(false)}
          messages={chatMessages}
          onSendMessage={handleAskAI}
          isLoading={isAiLoading}
          selectedVuln={selectedVuln}
        />
      )}

    </div>
  );
}

export default App;
