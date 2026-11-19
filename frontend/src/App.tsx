import { useState, useEffect, useRef } from 'react';

// Tipagens
interface Vulnerability {
  id: number;
  cve_id: string;
  title: string;
  description: string | null;
  vendor: string | null;
  product: string | null;
  severity: string | null;
  cvss_score: string | null;
  cisa_date_added: string | null;
  cisa_required_action: string | null;
  cisa_due_date: string | null;
  custom_risk_score: number | null;
  cvss_vector?: string | null;
  known_exploited?: boolean;
  ransomware_use?: boolean | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  has_ai_analysis?: boolean;
}

interface AiSource {
  title: string;
  url: string;
}

interface ScoreComponent {
  value: number;
  weight: number;
  points: number;
}

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const KEY_STORAGE = 'cyberpulse_gemini_key';

const SCORE_LABELS: Record<string, string> = {
  cvss: 'SEVERIDADE (CVSS)',
  epss: 'PROB. EXPLORAÇÃO (EPSS)',
  kev: 'EXPLORADA ATIVAMENTE (CISA)',
  ransomware: 'USADA POR RANSOMWARE',
  urgency: 'URGÊNCIA / RECÊNCIA',
};

// Lê a mensagem de erro da API mesmo quando a resposta não é JSON (ex: 502 do proxy do Render).
async function readError(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body?.detail === 'string') return body.detail;
    if (Array.isArray(body?.detail)) return 'REQUISIÇÃO INVÁLIDA';
  } catch {
    /* corpo não é JSON */
  }
  if (res.status === 429) return 'MUITAS REQUISIÇÕES. AGUARDE UM MINUTO.';
  if (res.status >= 500) return `SERVIDOR INDISPONÍVEL (HTTP ${res.status}). TENTE NOVAMENTE EM INSTANTES.`;
  return `FALHA NA REQUISIÇÃO (HTTP ${res.status})`;
}

function readStoredKey(): { key: string; remember: boolean } {
  try {
    const session = sessionStorage.getItem(KEY_STORAGE);
    if (session) return { key: session, remember: false };
    const local = localStorage.getItem(KEY_STORAGE);
    if (local) return { key: local, remember: true };
  } catch {
    /* storage bloqueado */
  }
  return { key: '', remember: false };
}

function App() {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Search State
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<'score' | 'recent'>('score');

  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  // API Key State
  const [apiKey, setApiKey] = useState('');
  const [isKeySaved, setIsKeySaved] = useState(false);
  const [rememberKey, setRememberKey] = useState(false);

  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [aiSources, setAiSources] = useState<AiSource[]>([]);
  const [aiMeta, setAiMeta] = useState<{ cached: boolean; generatedAt: string | null } | null>(null);
  const [scoreBreakdown, setScoreBreakdown] = useState<Record<string, ScoreComponent> | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const fetchData = (q: string = '', sortMode: string = sortBy) => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ lang: 'pt-br', sort: sortMode, limit: '100' });
    const query = q.trim().slice(0, 100);
    if (query) params.set('q', query);

    fetch(`${API_BASE_URL}/api/v1/vulnerabilities?${params}`)
      .then(async res => {
        if (!res.ok) throw new Error(await readError(res));
        return res.json();
      })
      .then((vulnsData: Vulnerability[]) => {
        setVulns(Array.isArray(vulnsData) ? vulnsData : []);
        setLoading(false);
      })
      .catch(err => {
        console.error("Erro ao buscar a API:", err);
        setError(err instanceof Error && err.message !== 'Failed to fetch'
          ? err.message
          : "FALHA DE COMUNICAÇÃO COM O SERVIDOR. ELE PODE ESTAR INICIANDO (ATÉ 1 MIN) — TENTE NOVAMENTE.");
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchData(searchQuery);

    const stored = readStoredKey();
    if (stored.key) {
      setApiKey(stored.key);
      setRememberKey(stored.remember);
      setIsKeySaved(true);
    }
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeModal();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchData(searchQuery, sortBy);
  };

  const handleSortChange = (newSort: 'score' | 'recent') => {
    setSortBy(newSort);
    fetchData(searchQuery, newSort);
  };

  const saveApiKey = () => {
    const key = apiKey.trim();
    if (key.length <= 10) {
      setAiError('CHAVE MUITO CURTA. COLE A CHAVE COMPLETA DO GOOGLE AI STUDIO.');
      return;
    }
    try {
      // Por padrão a chave vive só nesta aba (sessionStorage). "Lembrar" grava no localStorage.
      sessionStorage.removeItem(KEY_STORAGE);
      localStorage.removeItem(KEY_STORAGE);
      (rememberKey ? localStorage : sessionStorage).setItem(KEY_STORAGE, key);
    } catch {
      /* sem storage: a chave fica só em memória */
    }
    setApiKey(key);
    setAiError(null);
    setIsKeySaved(true);
  };

  const removeApiKey = () => {
    try {
      sessionStorage.removeItem(KEY_STORAGE);
      localStorage.removeItem(KEY_STORAGE);
    } catch {
      /* ignore */
    }
    setApiKey('');
    setIsKeySaved(false);
    setAiError(null);
  };

  const getSeverityBadge = (severity: string | null) => {
    if (!severity) return <span className="text-zinc-500 animate-pulse">[ ANALISANDO... ]</span>;
    const s = severity.toUpperCase();
    if (s === 'CRITICAL' || s === 'CRÍTICO') return <span className="text-red-500 font-bold border border-red-500/50 bg-red-950/30 px-2 py-0.5 shadow-[0_0_8px_rgba(239,68,68,0.3)]">[ CRÍTICO ]</span>;
    if (s === 'HIGH' || s === 'ALTO') return <span className="text-orange-500 font-bold border border-orange-500/50 bg-orange-950/30 px-2 py-0.5 shadow-[0_0_8px_rgba(249,115,22,0.3)]">[ ALTO ]</span>;
    if (s === 'MEDIUM' || s === 'MÉDIO') return <span className="text-yellow-500 font-bold border border-yellow-500/50 bg-yellow-950/30 px-2 py-0.5 shadow-[0_0_8px_rgba(234,179,8,0.3)]">[ MÉDIO ]</span>;
    if (s === 'LOW' || s === 'BAIXO') return <span className="text-emerald-500 font-bold border border-emerald-500/50 bg-emerald-950/30 px-2 py-0.5 shadow-[0_0_8px_rgba(16,185,129,0.3)]">[ BAIXO ]</span>;
    return <span className="text-emerald-500 font-bold border border-emerald-500/50 bg-emerald-950/30 px-2 py-0.5 shadow-[0_0_8px_rgba(16,185,129,0.3)]">[ {severity} ]</span>;
  };

  const getCustomScoreBadge = (score: number | null) => {
    if (score === null) return <span className="text-zinc-600 animate-pulse text-xs">[ CALC... ]</span>;
    if (score >= 8.0) return <span className="text-red-500 font-black shadow-[0_0_10px_rgba(239,68,68,0.5)]">[{score.toFixed(1)}]</span>;
    if (score >= 5.0) return <span className="text-orange-500 font-bold">[{score.toFixed(1)}]</span>;
    return <span className="text-emerald-500 font-bold">[{score.toFixed(1)}]</span>;
  }

  const formatDate = (dateString: string | null) => {
    if (!dateString) return '00/00/0000';
    return new Date(dateString).toLocaleDateString('pt-BR');
  };

  const renderAiAnalysis = (text: string) => {
    const lines = text.split('\n');
    let inCodeBlock = false;
    let codeContent: string[] = [];
    const elements: React.ReactNode[] = [];
    let currentList: React.ReactNode[] = [];
    let isOrderedList = false;

    const flushList = () => {
      if (currentList.length > 0) {
        elements.push(
          isOrderedList ? (
            <ol key={`ol-${elements.length}`} className="list-decimal list-outside ml-6 mb-4 text-zinc-300 font-sans leading-relaxed text-base opacity-90 marker:text-blue-500">
              {currentList}
            </ol>
          ) : (
            <ul key={`ul-${elements.length}`} className="list-disc list-outside ml-6 mb-4 text-zinc-300 font-sans leading-relaxed text-base opacity-90 marker:text-blue-500">
              {currentList}
            </ul>
          )
        );
        currentList = [];
      }
    };

    lines.forEach((line, index) => {
      const trimmedLine = line.trim();

      if (trimmedLine.startsWith('```')) {
        flushList();
        if (inCodeBlock) {
          elements.push(
            <pre key={`code-${index}`} className="bg-black text-emerald-400 p-4 rounded-md mb-4 overflow-x-auto font-mono text-sm border border-emerald-900/50 shadow-inner">
              <code>{codeContent.join('\n')}</code>
            </pre>
          );
          codeContent = [];
          inCodeBlock = false;
        } else {
          inCodeBlock = true;
        }
        return;
      }

      if (inCodeBlock) {
        codeContent.push(line);
        return;
      }

      const headingMatch = trimmedLine.match(/^\*\*(.+?)\*\*$/);
      if (headingMatch) {
        flushList();
        elements.push(
          <h4 key={`h4-${index}`} className="text-lg font-bold text-blue-400 mt-6 mb-3 uppercase tracking-wide border-l-2 border-blue-500 pl-3">
            {headingMatch[1]}
          </h4>
        );
        return;
      }

      const inlineHeadingMatch = trimmedLine.match(/^(?:#+\s*)?\*\*(.+?)\*\*:?\s*(.*)$/);
      if (inlineHeadingMatch && !trimmedLine.match(/^[-*1-9]/)) {
         if (!inlineHeadingMatch[2]) {
             flushList();
             elements.push(
               <h4 key={`h4-${index}`} className="text-lg font-bold text-blue-400 mt-6 mb-3 uppercase tracking-wide border-l-2 border-blue-500 pl-3">
                 {inlineHeadingMatch[1]}
               </h4>
             );
             return;
         }
      }

      const ulMatch = trimmedLine.match(/^[-*]\s+(.*)$/);
      if (ulMatch) {
        if (isOrderedList) flushList();
        isOrderedList = false;
        currentList.push(
          <li key={`li-${index}`} className="mb-1">{ulMatch[1]}</li>
        );
        return;
      }

      const olMatch = trimmedLine.match(/^(\d+)\.\s+(.*)$/);
      if (olMatch) {
        if (!isOrderedList) flushList();
        isOrderedList = true;
        currentList.push(
          <li key={`li-${index}`} className="mb-1">{olMatch[2]}</li>
        );
        return;
      }

      if (trimmedLine !== '') {
        flushList();
        const renderInlineStyles = (text: string) => {
          const parts = text.split(/(\*\*.*?\*\*)/g);
          return parts.map((part, i) => {
            if (part.startsWith('**') && part.endsWith('**')) {
              return <strong key={i} className="text-zinc-100 font-bold">{part.slice(2, -2)}</strong>;
            }
            const codeParts = part.split(/(`.*?`)/g);
            return codeParts.map((cp, j) => {
                if (cp.startsWith('`') && cp.endsWith('`')) {
                    return <code key={`${i}-${j}`} className="bg-zinc-800 text-emerald-300 px-1 py-0.5 rounded text-sm font-mono">{cp.slice(1, -1)}</code>;
                }
                return cp;
            });
          });
        };

        elements.push(
          <p key={`p-${index}`} className="mb-4 text-zinc-300 font-sans leading-relaxed text-base opacity-90">
            {renderInlineStyles(trimmedLine)}
          </p>
        );
      }
    });

    flushList();
    return elements;
  };

  const aiRequestController = useRef<AbortController | null>(null);

  const openVuln = (vuln: Vulnerability) => {
    setSelectedVuln(vuln);
    setAiAnalysis(null);
    setAiSources([]);
    setAiMeta(null);
    setAiError(null);
    setScoreBreakdown(null);

    const cve = encodeURIComponent(vuln.cve_id);
    fetch(`${API_BASE_URL}/api/v1/vulnerabilities/${cve}/score`)
      .then(res => (res.ok ? res.json() : null))
      .then(data => data && setScoreBreakdown(data.components))
      .catch(() => {});

    if (vuln.has_ai_analysis) {
      fetch(`${API_BASE_URL}/api/v1/vulnerabilities/${cve}/analysis`)
        .then(res => (res.ok ? res.json() : null))
        .then(data => {
          if (data?.ai_analysis) {
            setAiAnalysis(data.ai_analysis);
            setAiSources(Array.isArray(data.sources) ? data.sources : []);
            setAiMeta({ cached: true, generatedAt: data.generated_at });
          }
        })
        .catch(() => {});
    }
  };

  const handleAskAI = (cve_id: string, force = false) => {
    if (!isKeySaved) return;

    // Cancela a requisição anterior se houver
    if (aiRequestController.current) {
      aiRequestController.current.abort();
    }

    // Cria um novo controller para esta requisição
    aiRequestController.current = new AbortController();
    const signal = aiRequestController.current.signal;

    setIsAiLoading(true);
    setAiError(null);
    setAiAnalysis(null);
    setAiSources([]);
    setAiMeta(null);

    const url = `${API_BASE_URL}/api/v1/vulnerabilities/${encodeURIComponent(cve_id)}/analyze${force ? '?force=true' : ''}`;
    fetch(url, {
      method: 'POST',
      headers: {
        'X-Gemini-Key': apiKey.trim()
      },
      signal
    })
      .then(async (res) => {
        if (!res.ok) {
          if (res.status === 401) setIsKeySaved(false);
          throw new Error(await readError(res));
        }
        return res.json();
      })
      .then(data => {
        if (!signal.aborted) {
          setAiAnalysis(data.ai_analysis);
          setAiSources(Array.isArray(data.sources) ? data.sources : []);
          setAiMeta({ cached: Boolean(data.cached), generatedAt: data.generated_at });
          setVulns(prev => prev.map(v => (v.cve_id === cve_id ? { ...v, has_ai_analysis: true } : v)));
        }
      })
      .catch(err => {
        if (err.name === 'AbortError') {
          console.log('Requisição IA cancelada.');
          return;
        }
        if (!signal.aborted) {
          setAiError(err.message === 'Failed to fetch'
            ? 'SEM RESPOSTA DO SERVIDOR. ELE PODE ESTAR INICIANDO — TENTE NOVAMENTE EM 1 MINUTO.'
            : err.message);
        }
      })
      .finally(() => {
        if (!signal.aborted) {
          setIsAiLoading(false);
        }
      });
  };

  const closeModal = () => {
    if (aiRequestController.current) {
      aiRequestController.current.abort();
      aiRequestController.current = null;
    }
    setSelectedVuln(null);
    setAiAnalysis(null);
    setAiSources([]);
    setAiMeta(null);
    setScoreBreakdown(null);
    setAiError(null);
    setIsAiLoading(false);
  };

  return (
    <>
      <div className="crt-overlay"></div>
      <div className="scanline"></div>

      <div className="min-h-screen bg-zinc-950 font-['Fira_Code',monospace] text-emerald-500 pb-12 relative overflow-hidden">

        {/* Header Terminal */}
        <header className="border-b border-emerald-900/50 bg-black/80 backdrop-blur-sm sticky top-0 z-10 shadow-[0_4px_30px_rgba(0,0,0,0.5)]">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16 items-center">
              <div className="flex-shrink-0 flex items-center gap-3">
                <div className="w-10 h-10 border-2 border-emerald-500 flex items-center justify-center bg-emerald-950/50 shadow-[0_0_15px_rgba(16,185,129,0.4)]">
                  <span className="text-emerald-400 font-bold text-xl animate-pulse">_</span>
                </div>
                <div className="flex flex-col">
                  <span className="font-bold text-2xl tracking-widest text-emerald-400 uppercase drop-shadow-[0_0_8px_rgba(16,185,129,0.8)]">
                    CyberPulse
                  </span>
                  <span className="text-[10px] text-emerald-600 tracking-[0.2em] uppercase">Terminal de Inteligência de Ameaças v1.0</span>
                </div>
              </div>
            </div>
          </div>
        </header>

        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative z-0">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-64 gap-4">
              <div className="w-16 h-16 border-4 border-emerald-900 border-t-emerald-400 rounded-full animate-spin shadow-[0_0_15px_rgba(16,185,129,0.5)]"></div>
              <div className="text-emerald-400 text-sm tracking-[0.3em] uppercase animate-pulse">ESTABELECENDO CONEXÃO SEGURA...</div>
            </div>
          ) : error ? (
            <div className="p-8 border border-red-500/50 bg-red-950/20 text-center text-red-500 font-bold uppercase tracking-widest shadow-[0_0_20px_rgba(239,68,68,0.3)]">
              [ ERRO: {error} ]
            </div>
          ) : (
            <div className="space-y-12">



              {/* Tabela de Vulnerabilidades e Busca */}
              <section>
                <div className="mb-6 flex flex-col sm:flex-row justify-between items-end gap-4">
                  <div className="flex items-center gap-3 w-full sm:w-auto">
                    <div className="h-0.5 w-12 bg-emerald-900/50"></div>
                    <h2 className="text-xl font-bold text-red-500 uppercase tracking-[0.2em] drop-shadow-[0_0_8px_rgba(239,68,68,0.5)] whitespace-nowrap">AMEAÇAS ATIVAS</h2>
                    <div className="flex gap-2 ml-2">
                      <button
                        onClick={() => handleSortChange('score')}
                        className={`text-[9px] px-2 py-1 uppercase tracking-widest border transition-colors ${sortBy === 'score' ? 'border-emerald-500 bg-emerald-950/50 text-emerald-400 font-bold' : 'border-emerald-900/50 text-emerald-700 hover:text-emerald-500'}`}
                      >
                        CRITICIDADE
                      </button>
                      <button
                        onClick={() => handleSortChange('recent')}
                        className={`text-[9px] px-2 py-1 uppercase tracking-widest border transition-colors ${sortBy === 'recent' ? 'border-emerald-500 bg-emerald-950/50 text-emerald-400 font-bold' : 'border-emerald-900/50 text-emerald-700 hover:text-emerald-500'}`}
                      >
                        CISA_RECENTES
                      </button>
                    </div>
                    <div className="h-0.5 flex-grow bg-emerald-900/50 hidden lg:block"></div>
                  </div>

                  {/* Busca Hacker */}
                  <form onSubmit={handleSearch} className="flex w-full sm:w-auto">
                    <div className="flex items-center border border-emerald-800 bg-black px-3 py-1">
                      <span className="text-emerald-600 mr-2">&gt;_</span>
                      <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="PESQUISAR_CVE_OU_SISTEMA..."
                        className="bg-transparent border-none text-emerald-400 focus:outline-none uppercase text-xs tracking-widest placeholder-emerald-900/70 w-full sm:w-64"
                      />
                      <button type="submit" className="text-emerald-500 font-bold ml-2 hover:text-white transition-colors text-xs uppercase tracking-widest">
                        [ BUSCAR ]
                      </button>
                    </div>
                  </form>
                </div>

                <div className="mb-3 text-[10px] tracking-widest text-emerald-600/70 uppercase text-right">
                  {searchQuery
                    ? `[ BUSCA CONCLUÍDA: ENCONTRADAS ${vulns.length} AMEAÇAS PARA "${searchQuery}" ]`
                    : sortBy === 'score'
                      ? `[ SISTEMA EXIBINDO AS ${vulns.length} VULNERABILIDADES MAIS CRÍTICAS... ]`
                      : `[ SISTEMA EXIBINDO AS ${vulns.length} VULNERABILIDADES MAIS RECENTES... ]`}
                </div>

                <div className="bg-black/50 border border-emerald-900/50 shadow-[0_0_30px_rgba(0,0,0,0.8)] overflow-hidden relative">
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-emerald-900/30">
                      <thead className="bg-emerald-950/20">
                        <tr>
                          <th className="py-4 pl-4 pr-3 text-left text-[11px] uppercase tracking-widest text-emerald-600 sm:pl-6">RISK SCORE (CYBERPULSE)</th>
                          <th className="px-3 py-4 text-left text-[11px] uppercase tracking-widest text-emerald-600">ID DA AMEAÇA</th>
                          <th className="px-3 py-4 text-left text-[11px] uppercase tracking-widest text-emerald-600">DESCRIÇÃO (ALVO)</th>
                          <th className="px-3 py-4 text-left text-[11px] uppercase tracking-widest text-emerald-600">NÍVEL CVSS</th>
                          <th className="px-3 py-4 text-left text-[11px] uppercase tracking-widest text-emerald-600">AÇÃO</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-emerald-900/20 bg-transparent">
                        {vulns.length === 0 ? (
                          <tr>
                            <td colSpan={5} className="py-12 text-center text-emerald-600 uppercase tracking-widest">NENHUM REGISTRO ENCONTRADO</td>
                          </tr>
                        ) : (
                          vulns.map((vuln) => (
                            <tr
                              key={vuln.id}
                              className="hover:bg-emerald-900/20 transition-all cursor-pointer group"
                              onClick={() => openVuln(vuln)}
                            >
                              <td className="whitespace-nowrap py-4 pl-4 pr-3 sm:pl-6 text-sm">
                                {getCustomScoreBadge(vuln.custom_risk_score)}
                              </td>
                              <td className="whitespace-nowrap py-4 px-3 text-sm font-bold text-emerald-500 group-hover:text-emerald-300">
                                {vuln.cve_id}
                              </td>
                              <td className="py-4 px-3 text-sm">
                                <div className="font-medium text-zinc-300 max-w-sm truncate uppercase group-hover:text-white" title={vuln.title}>{vuln.title}</div>
                                <div className="text-[10px] text-zinc-500 mt-1 tracking-widest flex items-center gap-2">
                                  <span>ALVO: {vuln.vendor} {vuln.product}</span>
                                  <span className="text-zinc-700">|</span>
                                  <span className="text-emerald-600">CISA: {vuln.cisa_date_added ? formatDate(vuln.cisa_date_added) : 'N/A'}</span>
                                  {vuln.ransomware_use && <span className="text-red-500 font-bold">RANSOMWARE</span>}
                                  {vuln.epss_score != null && <span className="text-zinc-400">EPSS {(vuln.epss_score * 100).toFixed(1)}%</span>}
                                </div>
                              </td>
                              <td className="whitespace-nowrap py-4 px-3 text-xs">
                                {getSeverityBadge(vuln.severity)}
                              </td>
                              <td className="whitespace-nowrap py-4 px-3 text-xs">
                                 <button className="text-emerald-500 font-bold text-[10px] border border-emerald-700 bg-black px-3 py-1.5 uppercase tracking-widest group-hover:bg-emerald-500 group-hover:text-black group-hover:shadow-[0_0_10px_rgba(16,185,129,0.5)] transition-all">
                                   &gt; DETALHES
                                 </button>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </section>

            </div>
          )}
        </main>

        {/* MODAL IA / TERMINAL DE DETALHES DA VULNERABILIDADE */}
        {selectedVuln && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm transition-opacity">
            <div className="bg-zinc-950 border border-emerald-500/50 shadow-[0_0_40px_rgba(16,185,129,0.2)] w-full max-w-[95vw] max-h-[95vh] overflow-hidden flex flex-col relative animate-in fade-in zoom-in-95 duration-200">

              {/* Top Bar Terminal */}
              <div className="bg-emerald-950/50 border-b border-emerald-900/50 p-2 flex justify-between items-center">
                <div className="flex gap-2 items-center px-2">
                  <span className="text-red-500 font-bold text-xs uppercase animate-pulse">● FEED_AO_VIVO</span>
                  <span className="text-emerald-600 text-xs font-medium">| root@cyberpulse:~# cat threat_intel.log</span>
                </div>
                <button
                  onClick={closeModal}
                  className="text-emerald-500 hover:text-white hover:bg-red-500 px-3 py-1 text-xs font-bold transition-colors uppercase border border-transparent hover:border-red-400"
                >
                  [X] FECHAR
                </button>
              </div>

              <div className="overflow-y-auto p-6 sm:p-8 flex-grow cyber-scrollbar">

                <div className="mb-8 pb-6 border-b border-emerald-900/30">
                  <div className="flex items-center gap-4 mb-3">
                    <span className="bg-emerald-500 text-black px-3 py-1 text-sm font-black tracking-widest uppercase shadow-[0_0_10px_rgba(16,185,129,0.4)]">
                      {selectedVuln.cve_id}
                    </span>
                    {getCustomScoreBadge(selectedVuln.custom_risk_score)}
                  </div>
                  <h2 className="text-2xl font-bold text-white uppercase tracking-wide">{selectedVuln.title}</h2>
                  <div className="mt-3 text-xs tracking-widest text-zinc-400 flex flex-wrap gap-x-6 gap-y-2">
                    <span><strong className="text-emerald-600">FABRICANTE:</strong> {selectedVuln.vendor || 'DESCONHECIDO'}</span>
                    <span><strong className="text-emerald-600">PRODUTO:</strong> {selectedVuln.product || 'DESCONHECIDO'}</span>
                    <span><strong className="text-emerald-600">CVSS:</strong> {selectedVuln.cvss_score || 'PENDENTE'}</span>
                    {selectedVuln.epss_score != null && (
                      <span><strong className="text-emerald-600">EPSS:</strong> {(selectedVuln.epss_score * 100).toFixed(1)}% (PERCENTIL {Math.round((selectedVuln.epss_percentile ?? 0) * 100)})</span>
                    )}
                    {selectedVuln.ransomware_use && <span className="text-red-500 font-bold">USADA EM CAMPANHAS DE RANSOMWARE</span>}
                  </div>
                  {scoreBreakdown && (
                    <div className="mt-4 grid grid-cols-1 sm:grid-cols-5 gap-2">
                      {Object.entries(scoreBreakdown).map(([k, c]) => (
                        <div key={k} className="border border-emerald-900/40 bg-black/40 px-3 py-2" title={`Peso ${Math.round(c.weight * 100)}%`}>
                          <div className="text-[9px] text-emerald-700 tracking-widest">{SCORE_LABELS[k] ?? k.toUpperCase()}</div>
                          <div className="text-sm text-emerald-400 font-bold">+{c.points.toFixed(1)} <span className="text-[9px] text-zinc-600">/ {(c.weight * 10).toFixed(1)}</span></div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex flex-col gap-8">

                  {/* Top Row: Dados Brutos */}
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div className="border border-zinc-800 bg-zinc-900/50 p-4 flex flex-col">
                      <h4 className="text-[10px] font-bold text-emerald-600 uppercase tracking-widest mb-3 border-b border-zinc-800 pb-2 flex-shrink-0">
                        DESCRIÇÃO_TÉCNICA_BRUTA
                      </h4>
                      <p className="text-zinc-400 text-xs leading-relaxed font-sans overflow-y-auto max-h-32 cyber-scrollbar">
                        {selectedVuln.description || 'N/A'}
                      </p>
                    </div>

                    <div className="border border-orange-500/30 bg-orange-950/20 p-4 relative flex flex-col">
                      <div className="absolute top-0 left-0 w-1 h-full bg-orange-500"></div>
                      <h4 className="text-[10px] font-bold text-orange-500 uppercase tracking-widest mb-3 border-b border-orange-900/50 pb-2 flex-shrink-0">
                        AÇÃO_OBRIGATÓRIA_CISA
                      </h4>
                      <div className="overflow-y-auto max-h-32 cyber-scrollbar">
                        <p className="text-orange-200 text-xs leading-relaxed font-sans font-medium">
                          {selectedVuln.cisa_required_action || 'NENHUMA DIRETIVA ENCONTRADA.'}
                        </p>
                        {selectedVuln.cisa_due_date && (
                          <p className="text-orange-500 text-[10px] mt-4 font-bold tracking-widest bg-black inline-block px-2 py-1 border border-orange-900">
                            PRAZO FINAL: {formatDate(selectedVuln.cisa_due_date)}
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="flex flex-col justify-end">
                      <a
                        href={`https://www.cve.org/CVERecord?id=${selectedVuln.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-2 border border-emerald-500/30 bg-emerald-950/10 px-4 py-3 text-xs font-bold text-emerald-500 uppercase tracking-widest hover:bg-emerald-900/40 hover:border-emerald-500 hover:text-emerald-400 transition-all w-full justify-center shadow-[0_0_10px_rgba(16,185,129,0.05)] hover:shadow-[0_0_15px_rgba(16,185,129,0.2)]"
                      >
                        &gt;&gt; ACESSAR PÁGINA OFICIAL ({selectedVuln.cve_id})
                      </a>
                    </div>
                  </div>

                  {/* Bottom Area: IA */}
                  <div className="flex flex-col gap-6 w-full flex-grow mt-4">
                    <div className="border border-blue-500/30 bg-blue-950/10 flex flex-col relative overflow-hidden min-h-[50vh]">
                      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-600 to-indigo-600 z-10"></div>

                      {/* Cabeçalho Fixo */}
                      <div className="p-5 border-b border-blue-900/50 bg-blue-950/20 sticky top-0 z-10 flex-shrink-0">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                          <div>
                            <h3 className="font-bold text-blue-400 flex items-center gap-2 uppercase tracking-wider text-sm">
                              <span className="animate-spin text-lg">⚙</span> MOTOR_DE_ANALISE_IA
                            </h3>
                            <p className="text-[10px] text-zinc-500 mt-1 uppercase tracking-widest">Executa roteiro de tradução com IA Gemini.</p>
                          </div>

                          {isKeySaved ? (
                            !isAiLoading && (
                              <div className="flex flex-col items-end gap-2">
                                <button
                                  onClick={() => handleAskAI(selectedVuln.cve_id, Boolean(aiAnalysis))}
                                  className="bg-black border border-blue-500 text-blue-400 hover:bg-blue-500 hover:text-black hover:shadow-[0_0_15px_rgba(59,130,246,0.6)] font-bold py-2 px-4 transition-all text-xs uppercase tracking-widest flex-shrink-0"
                                >
                                  {aiAnalysis ? '>_ GERAR_NOVAMENTE.SH' : (aiError ? '>_ TENTAR_NOVAMENTE.SH' : '>_ EXECUTAR_SIMPLIFICACAO.SH')}
                                </button>
                                <button onClick={removeApiKey} className="text-[9px] text-zinc-500 hover:text-red-400 uppercase tracking-widest underline">Desconectar Token</button>
                              </div>
                            )
                          ) : (
                            <div className="flex flex-col gap-2 w-full max-w-xs mt-4 sm:mt-0">
                              <input
                                type="password"
                                value={apiKey}
                                onChange={(e) => setApiKey(e.target.value)}
                                placeholder="INSIRA SUA API KEY DO GEMINI..."
                                className="bg-black border border-blue-800 text-blue-400 p-2 text-xs w-full focus:outline-none focus:border-blue-400"
                              />
                              <label className="flex items-center gap-2 text-[9px] text-zinc-500 uppercase tracking-widest cursor-pointer">
                                <input type="checkbox" checked={rememberKey} onChange={(e) => setRememberKey(e.target.checked)} className="accent-blue-500" />
                                Lembrar neste navegador
                              </label>
                              <div className="flex justify-between items-center">
                                <a href="https://aistudio.google.com/app/apikey"  target="_blank" rel="noopener noreferrer" className="text-[9px] text-blue-600 hover:text-blue-400 uppercase underline">
                                  Obter Token Gratuito
                                </a>
                                <button onClick={saveApiKey} className="text-xs bg-blue-900/50 hover:bg-blue-600 border border-blue-500 text-blue-300 font-bold py-1 px-3 uppercase">
                                  Salvar
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Área da Resposta (Scrollável) */}
                      <div className="p-5 overflow-y-auto cyber-scrollbar flex-grow">
                        {isAiLoading && (
                          <div className="text-xs text-blue-400 font-mono flex flex-col gap-2">
                            <div><span className="text-zinc-500">[SISTEMA]</span> Autenticando Token...</div>
                            <div><span className="text-zinc-500">[SISTEMA]</span> Executando pesquisa online em bases de ameaças...</div>
                            <div><span className="text-zinc-500">[SISTEMA]</span> Analisando vetores de vulnerabilidade e extraindo KBs...</div>
                            <div className="animate-pulse flex items-center gap-2 mt-2">
                              <div className="w-2 h-4 bg-blue-500 animate-bounce"></div> GERANDO RESPOSTA...
                            </div>
                          </div>
                        )}

                        {aiError && (
                          <div className="text-xs text-red-500 bg-red-950/30 p-3 border border-red-900 font-mono">
                            [FALHA_CRÍTICA] {aiError}
                          </div>
                        )}

                        {aiAnalysis && (
                          <div className="text-zinc-300 text-sm leading-relaxed prose prose-invert max-w-none">
                            <div className="text-[10px] text-blue-500 mb-4 tracking-widest border-b border-blue-900/50 pb-2">
                              // SAIDA_IA_SUCESSO
                              {aiMeta?.generatedAt && (
                                <span className="text-zinc-600 ml-2">
                                  {aiMeta.cached ? '(ANÁLISE SALVA DE ' : '(GERADA EM '}
                                  {new Date(aiMeta.generatedAt + (aiMeta.generatedAt.endsWith('Z') ? '' : 'Z')).toLocaleString('pt-BR')})
                                </span>
                              )}
                            </div>
                            {renderAiAnalysis(aiAnalysis)}
                            {aiSources.length > 0 && (
                              <div className="mt-6 border-t border-blue-900/50 pt-3">
                                <h4 className="text-[10px] font-bold text-blue-500 uppercase tracking-widest mb-2">FONTES CONSULTADAS PELA IA</h4>
                                <ul className="list-disc ml-6 text-xs">
                                  {aiSources.filter(src => src.url.startsWith('https://')).map(src => (
                                    <li key={src.url}>
                                      <a href={src.url} target="_blank" rel="noopener noreferrer" className="text-blue-400 underline hover:text-blue-300">{src.title}</a>
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            <p className="mt-4 text-[10px] text-zinc-600 uppercase tracking-widest">Conteúdo gerado por IA: confirme KBs e versões na página oficial do fabricante antes de aplicar.</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}



      </div>
    </>
  );
}

export default App;
