import React, { useState, useRef, useEffect } from 'react';
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
import { Vulnerability, ChatMessage, ScanHistoryRecord, FilteredNoiseItem } from './types';
import { scanEntry, resolveIntent, generateFix, rescanTarget } from './api/nullify';

// ── 스캔 세션(대화) 로컬 히스토리 — 브라우저 localStorage 에 저장, 스캔마다 갱신 ──
const SESS_KEY = 'nullify_sessions';
interface ScanSession {
  id: string;
  label: string;
  ts: string;
  mode: 'detect' | 'source' | 'combined';
  canFix: boolean;
  summary: { total: number; crit: number; ques: number; warn: number };
  vulnerabilities: Vulnerability[];
  filteredNoise: FilteredNoiseItem[];
}
function loadSessions(): ScanSession[] {
  try { return JSON.parse(localStorage.getItem(SESS_KEY) || '[]'); } catch { return []; }
}
function persistSessions(s: ScanSession[]) {
  try { localStorage.setItem(SESS_KEY, JSON.stringify(s.slice(0, 50))); } catch { /* 용량초과 등 무시 */ }
}
function labelOf(url: string, repo: string): string {
  const pick = (repo || url || '').trim();
  return pick.replace(/^https?:\/\//, '').replace('github.com/', '').replace(/\.git$/, '').replace(/\/$/, '')
    || '로컬 데모 과녁';
}

export function App() {
  const [currentTab, setCurrentTab] = useState<'landing' | 'scanning' | 'analysis' | 'fix' | 'verify'>('landing');
  // 백엔드는 로컬 전용(127.0.0.1) + 공개 URL 거부이므로 기본 대상은 데모 과녁 앱.
  const [repoUrl, setRepoUrl] = useState<string>('http://127.0.0.1:8009');
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanNotice, setScanNotice] = useState<string | null>(null);   // 0건 등 정보성 안내
  const [canFix, setCanFix] = useState<boolean>(false);   // 소스 레포가 있어 '수정' 제공 가능?
  const [sessions, setSessions] = useState<ScanSession[]>([]);       // 스캔 대화 히스토리
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const scanningRef = useRef<boolean>(false);   // 실제 스캔 진행중? (애니메이션과 경합 방지)

  useEffect(() => { setSessions(loadSessions()); }, []);   // 최초 로드 시 히스토리 복원
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

  // Handlers — 사이트 URL(선택) + 레포(선택) 를 함께 받는다.
  const handleStartScan = async (url: string, repo: string = '') => {
    setRepoUrl(repo ? `${url || repo}${url && repo ? '  +  ' + repo : ''}` : url);
    setScanError(null);
    setScanNotice(null);
    setCurrentTab('scanning');
    scanningRef.current = true;
    try {
      // URL만 → 탐지 전용 / 레포만 → SAST / 둘다 → 완전체(수정 가능).
      const { vulnerabilities: vulns, filteredNoise: noise, mode, canFix } = await scanEntry(url, repo);
      setVulnerabilities(vulns);
      setFilteredNoise(noise);
      setCanFix(canFix);
      if (vulns.length) setSelectedVuln(vulns[0]);
      // 레포만(SAST) 스캔: 런타임 항목(보안헤더·노출시크릿·구버전컴포넌트)은
      // 소스만으론 못 봄 → 사이트 URL도 함께 넣어야 한다고 안내(핵심 혼란 방지).
      if (mode === 'source') {
        setScanNotice(vulns.length
          ? '소스(SAST) 결과입니다. 보안 헤더·런타임 노출 같은 항목은 코드만으론 못 봐요 — 사이트 URL도 함께 넣으면 완전체로 검사됩니다.'
          : '정적 탐지 0건 — 하드코딩 시크릿 없음. 보안 헤더 등 런타임 항목은 사이트 URL을, 깊은 코드 분석은 semgrep 설치를 함께 하세요.');
      } else if (mode === 'detect') {
        setScanNotice(vulns.length
          ? '탐지 전용 모드 — 발견만 표시합니다. 검증된 수정/PR을 받으려면 소스 레포도 함께 올리세요.'
          : '발견된 취약점 없음 — 이 대상에서 재현되는 취약점을 찾지 못했습니다.');
      } else if (!vulns.length) {
        setScanNotice('재현/정적 모두에서 취약점을 찾지 못했습니다.');
      }
      // 이 스캔을 히스토리(대화 목록)에 저장 — 스캔할 때마다 갱신.
      const summary = {
        total: vulns.length,
        crit: vulns.filter((v) => v.severity === 'high' && v.status !== 'pending_intent').length,
        ques: vulns.filter((v) => v.status === 'pending_intent').length,
        warn: vulns.filter((v) => v.severity === 'medium').length,
      };
      const session: ScanSession = {
        id: String(Date.now()),
        label: labelOf(url, repo),
        ts: new Date().toLocaleString('ko-KR', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }),
        mode, canFix, summary, vulnerabilities: vulns, filteredNoise: noise,
      };
      setSessions((prev) => { const next = [session, ...prev].slice(0, 50); persistSessions(next); return next; });
      setActiveSessionId(session.id);
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

  // 히스토리 항목 클릭 → 그때 분석하던 결과를 그대로 복원(재스캔 없음).
  const handleSelectSession = (id: string) => {
    const s = sessions.find((x) => x.id === id);
    if (!s) return;
    setVulnerabilities(s.vulnerabilities);
    setFilteredNoise(s.filteredNoise);
    setCanFix(s.canFix);
    if (s.vulnerabilities.length) setSelectedVuln(s.vulnerabilities[0]);
    setRepoUrl(s.label);
    setActiveSessionId(id);
    setScanError(null);
    setScanNotice(null);
    setCurrentTab('analysis');
  };

  // 새 스캔 = 새 대화 시작(입력 화면으로).
  const handleNewScan = () => {
    setActiveSessionId(null);
    setScanError(null);
    setScanNotice(null);
    setCurrentTab('landing');
  };

  const handleSelectVuln = (vuln: Vulnerability) => {
    setSelectedVuln(vuln);
  };

  const handleOpenIntentModal = (vuln: Vulnerability) => {
    setIntentTargetVuln(vuln);
    setIsIntentModalOpen(true);
  };

  const handleConfirmIntent = async (vulnId: string, isPrivate: boolean) => {
    const target = vulnerabilities.find((v) => v.id === vulnId);
    setIsIntentModalOpen(false);
    if (!target) return;
    try {
      // 백엔드 /api/resolve 실호출 — 판정은 백엔드 결정론이 내린다.
      const r = await resolveIntent(target, isPrivate);
      if (r.verdict === 'CONFIRMED') {
        // owner_only → 진짜 IDOR 확정. 검증된 수정/영수증까지 vuln 에 반영.
        const updated: Vulnerability = {
          ...target,
          requiresIntentConfirmation: false,
          status: 'unresolved',
          statusText: '미해결 (확정)',
          description: r.description,
          codeSnippet: r.codeSnippet || target.codeSnippet,
          receipt: r.receipt || target.receipt,
        };
        setVulnerabilities((prev) => prev.map((v) => (v.id === vulnId ? updated : v)));
        setSelectedVuln(updated);
        setCurrentTab('fix');   // 편의상 바로 수정 화면으로
      } else {
        // public → 공개 데이터로 확인 → 오탐 처리, 노이즈로 이동.
        setVulnerabilities((prev) =>
          prev.map((v) => (v.id === vulnId
            ? { ...v, status: 'ignored', statusText: '공개 정책 확인됨', requiresIntentConfirmation: false }
            : v)));
        setFilteredNoise((prev) => [
          { id: `noise-${Date.now()}`, type: target.type, endpoint: target.endpoint,
            reason: r.description || '사용자 확인: 공개 리소스로 판명되어 목록에서 제외.',
            category: 'false_positive' },
          ...prev,
        ]);
      }
    } catch (e: any) {
      setScanError(`의도 확인 처리 실패: ${e?.message || e}`);
    }
  };

  const handleNavigateToFix = (vuln: Vulnerability) => {
    setSelectedVuln(vuln);
    setCurrentTab('fix');
  };

  const handleGeneratePatch = async (vuln: Vulnerability) => {
    // 백엔드 /api/pr 실호출 — 실제 git 브랜치·커밋 생성(push/PR 만 사용자 몫).
    try {
      const fix = await generateFix(vuln);
      const prInfo = fix.ok
        ? { branch: fix.branch, commit: fix.commit, title: fix.title, gh: fix.gh,
            fixSource: fix.fixSource, recommendation: fix.recommendation }
        : { error: fix.error, needsReview: fix.needsReview, needsRepo: fix.needsRepo,
            detectionOnly: fix.detectionOnly, reason: fix.reason };
      // 설정 권고(recommendation)도 '해결'로 본다(소스 수정 불필요). 코드 PR 실패는 상태 유지.
      const resolved = fix.ok;
      const label = fix.recommendation ? '수정 완료 (설정 권고)'
                  : fix.ok ? '수정 완료 (git 커밋 생성됨)' : vuln.statusText;
      setVulnerabilities((prev) =>
        prev.map((v) =>
          v.id === vuln.id
            ? { ...v, status: resolved ? 'resolved' : v.status, statusText: label,
                ...(({ _pr: prInfo } as any)) }
            : v));
      setSelectedVuln((cur) => (cur.id === vuln.id
        ? { ...cur, status: resolved ? 'resolved' : cur.status, ...(({ _pr: prInfo } as any)) }
        : cur));
    } catch (e: any) {
      setScanError(`수정 생성 실패: ${e?.message || e}`);
    }
  };

  // 재검증: 백엔드가 패치 후 같은 공격을 다시 돌려 이전 스캔과 비교.
  const handleRescan = async () => {
    try {
      const { vulnerabilities: vulns, filteredNoise: noise } = await rescanTarget(repoUrl);
      setVulnerabilities(vulns);
      setFilteredNoise(noise);
    } catch (e: any) {
      setScanError(`재검증 실패: ${e?.message || e}`);
    }
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

  // 워크스페이스 크롬(사이드바+상단 스텝퍼) 표시 여부:
  // 스캐닝 중엔 전체화면, '처음 랜딩(기록 없음)'만 마케팅 화면. 그 외엔 워크스페이스.
  const showChrome = currentTab !== 'scanning' && !(currentTab === 'landing' && sessions.length === 0);

  return (
    <div className="min-h-screen bg-[#f7faf9] text-[#181c1c] flex flex-col font-sans selection:bg-[#a6f0ea] selection:text-[#00201e]">
      
      {/* Top Navbar — 워크스페이스에선 진행 단계 스텝퍼 */}
      <TopNavbar
        currentTab={currentTab}
        onNavigateTab={(tab) => setCurrentTab(tab)}
        onOpenSettings={() => setIsSettingsModalOpen(true)}
        onConnectClick={handleNewScan}
        onNewScan={handleNewScan}
        repoUrl={repoUrl}
        canFix={canFix}
        variant={showChrome ? 'workspace' : 'public'}
      />

      {/* 스캔 오류 배너 (백엔드 미기동/권한거부/인증 등) */}
      {scanError && (
        <div className="bg-[#fdecea] border-b border-[#f5c6c0] text-[#a11c10] px-4 py-2 text-[13px] text-center">
          스캔 실패: {scanError}
          <span className="text-[#7a1409]"> — 백엔드가 켜져 있는지(python web.py), 대상이 로컬/사설망인지 확인하세요.</span>
        </div>
      )}

      {/* 정보성 안내(0건 등) */}
      {scanNotice && !scanError && (
        <div className="bg-[#e7f1fd] border-b border-[#bcd8f5] text-[#1a4d80] px-4 py-2 text-[13px] text-center">
          {scanNotice}
        </div>
      )}

      {/* Main Workspace Layout — 좌측: 스캔 대화 히스토리 */}
      <div className="flex-1 flex w-full">
        {showChrome && (
          <Sidebar
            history={sessions.map((s) => ({
              id: s.id, label: s.label, ts: s.ts, mode: s.mode,
              total: s.summary.total, crit: s.summary.crit, ques: s.summary.ques, warn: s.summary.warn,
            }))}
            activeId={activeSessionId}
            onSelectSession={handleSelectSession}
            onNewScan={handleNewScan}
          />
        )}

        <main
          className={`flex-1 transition-all ${showChrome ? 'md:ml-64 pt-16' : ''}`}
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
              canFix={canFix}
            />
          )}

          {currentTab === 'fix' && (
            <FixDiffView
              vuln={selectedVuln}
              onGeneratePatch={handleGeneratePatch}
              onNavigateToVerify={handleNavigateToVerify}
              onSelectVuln={handleSelectVuln}
              allVulnerabilities={vulnerabilities}
              canFix={canFix}
            />
          )}

          {currentTab === 'verify' && (
            <VerificationView
              vulnerabilities={vulnerabilities}
              onOpenReceipt={handleOpenReceipt}
              onNavigateToAnalysis={handleNavigateToFix}
              onAskAI={handleAskAI}
              isAiLoading={isAiLoading}
              onRescan={handleRescan}
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
