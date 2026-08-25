export type VulnerabilitySeverity = 'high' | 'medium' | 'low';
export type VulnerabilityStatus = 'unresolved' | 'pending_intent' | 'resolved' | 'ignored';

export interface CodeSnippet {
  fileName: string;
  beforeCode: string;
  afterCode: string;
  problemLine: number;
  fixLine: number;
  highlightBefore?: string;
  highlightAfter?: string;
}

export interface ExploitReceipt {
  timestamp: string;
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  payload: string;
  beforeResponse: {
    status: number;
    headers: Record<string, string>;
    body: string;
    vulnerable: boolean;
  };
  afterResponse: {
    status: number;
    headers: Record<string, string>;
    body: string;
    vulnerable: boolean;
  };
  proofSummary: string;
}

export interface Vulnerability {
  id: string;
  type: string; // 'IDOR' | 'SQLi' | 'XSS' etc.
  endpoint: string;
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  status: VulnerabilityStatus;
  statusText: string;
  selected?: boolean;
  requiresIntentConfirmation?: boolean;
  intentQuestion?: {
    title: string;
    badgeText: string;
    reasonText: string;
    coreQuestion: string;
    highlightedPart: string;
    yesOption: {
      label: string;
      outcome: string;
    };
    noOption: {
      label: string;
      outcome: string;
    };
  };
  aiGuide: {
    title: string;
    explanation: string;
    fixDirection: string;
    bestPracticeTip: string;
  };
  codeSnippet: CodeSnippet;
  receipt?: ExploitReceipt;
}

export interface FilteredNoiseItem {
  id: string;
  type: string;
  endpoint: string;
  reason: string;
  category: 'unreachable' | 'dead_code' | 'sanitized_upstream' | 'false_positive';
}

export interface ScanHistoryRecord {
  id: string;
  repoUrl: string;
  date: string;
  totalFound: number;
  resolved: number;
  unresolved: number;
  status: 'completed' | 'in_progress' | 'verified';
}

export interface ChatMessage {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  timestamp: string;
  codeSnippet?: string;
}
