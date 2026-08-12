import { useState, useEffect } from 'react';

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
}

interface Advisory {
  id: number;
  title: string;
  vendor: string;
  description: string;
  source_url: string;
  published_at: string | null;
}

function App() {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [advisories, setAdvisories] = useState<Advisory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Fase 7: Search State
  const [searchQuery, setSearchQuery] = useState('');

  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [selectedAdvisory, setSelectedAdvisory] = useState<Advisory | null>(null);
  
  // Fase 9: API Key State
  const [apiKey, setApiKey] = useState('');
  const [isKeySaved, setIsKeySaved] = useState(false);

  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const fetchData = (q: string = '') => {
    setLoading(true);
    const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    let vulnsUrl = `${API_BASE_URL}/api/v1/vulnerabilities?lang=pt-br`;
    if (q) vulnsUrl += `&q=${encodeURIComponent(q)}`;
    
    Promise.all([
      fetch(vulnsUrl).then(res => res.json()),
      fetch(`${API_BASE_URL}/api/v1/advisories?lang=pt-br`).then(res => res.json())
    ])
      .then(([vulnsData, advisoriesData]) => {
        setVulns(vulnsData);
        setAdvisories(advisoriesData);
        setLoading(false);
      })
      .catch(err => {
        console.error("Erro ao buscar a API:", err);
        setError("FALHA CRÍTICA DE COMUNICAÇÃO COM O SERVIDOR PRINCIPAL.");
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchData(searchQuery);
    
    // Recupera a chave do LocalStorage se existir
    const savedKey = localStorage.getItem('cyberpulse_gemini_key');
    if (savedKey) {
      setApiKey(savedKey);
      setIsKeySaved(true);
    }
  }, []); 

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchData(searchQuery);
  };

  const saveApiKey = () => {
    if (apiKey.trim().length > 10) {
      localStorage.setItem('cyberpulse_gemini_key', apiKey.trim());
      setIsKeySaved(true);
    }
  };

  const removeApiKey = () => {
    localStorage.removeItem('cyberpulse_gemini_key');
    setApiKey('');
    setIsKeySaved(false);
    setAiAnalysis(null);
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

  const stripHtml = (html: string) => {
    const tmp = document.createElement("DIV");
    tmp.innerHTML = html;
    return tmp.textContent || tmp.innerText || "";
  };

  const handleAskAI = (cve_id: string) => {
    if (!isKeySaved) return;
    
    setIsAiLoading(true);
    setAiError(null);
    setAiAnalysis(null);
    
    const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    
    fetch(`${API_BASE_URL}/api/v1/vulnerabilities/${cve_id}/analyze`, { 
      method: 'POST',
      headers: {
        'X-Gemini-Key': apiKey.trim()
      }
    })
      .then(async (res) => {
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || 'CONEXÃO RECUSADA');
        }
        return res.json();
      })
      .then(data => {
        setAiAnalysis(data.ai_analysis);
      })
      .catch(err => {
        setAiError(err.message);
      })
      .finally(() => {
        setIsAiLoading(false);
      });
  };

  const closeModal = () => {
    setSelectedVuln(null);
    setSelectedAdvisory(null);
    setAiAnalysis(null);
    setAiError(null);
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
              
              {/* Notícias e Alertas (RSS) */}
              <section>
                <div className="mb-6 flex items-center gap-3">
                  <div className="h-0.5 flex-grow bg-emerald-900/50"></div>
                  <h2 className="text-xl font-bold text-emerald-400 uppercase tracking-[0.2em]">FONTES DE NOTÍCIAS (INTEL)</h2>
                  <div className="h-0.5 w-12 bg-emerald-900/50"></div>
                </div>
                
                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                  {advisories.map(adv => (
                    <div 
                      key={adv.id} 
                      onClick={() => setSelectedAdvisory(adv)}
                      className="block group h-full cursor-pointer"
                    >
                      <div className="bg-zinc-950 p-4 border border-emerald-900/40 group-hover:border-emerald-500/70 group-hover:bg-emerald-950/20 transition-all group-hover:shadow-[0_0_15px_rgba(16,185,129,0.15)] h-full flex flex-col relative overflow-hidden">
                        
                        {/* Decoradores Hacker */}
                        <div className="absolute top-0 left-0 w-2 h-2 border-t border-l border-emerald-500 opacity-0 group-hover:opacity-100 transition-opacity"></div>
                        <div className="absolute top-0 right-0 w-2 h-2 border-t border-r border-emerald-500 opacity-0 group-hover:opacity-100 transition-opacity"></div>
                        <div className="absolute bottom-0 left-0 w-2 h-2 border-b border-l border-emerald-500 opacity-0 group-hover:opacity-100 transition-opacity"></div>
                        <div className="absolute bottom-0 right-0 w-2 h-2 border-b border-r border-emerald-500 opacity-0 group-hover:opacity-100 transition-opacity"></div>

                        <div className="flex justify-between items-start mb-2">
                          <span className="text-[9px] uppercase tracking-widest text-zinc-400">
                            FONTE: <span className="text-emerald-500">{adv.vendor}</span>
                          </span>
                          <span className="text-[9px] text-zinc-500">{formatDate(adv.published_at)}</span>
                        </div>
                        
                        <h3 className="font-bold text-zinc-200 text-xs mb-3 group-hover:text-emerald-400 transition-colors line-clamp-3 uppercase flex-grow" title={adv.title}>
                          {adv.title}
                        </h3>
                        
                        <div className="flex justify-end mt-auto pt-2 border-t border-emerald-900/20">
                          <span className="text-[9px] font-bold text-emerald-700 group-hover:text-emerald-400 transition-colors uppercase tracking-widest">LER AVISO &gt;&gt;</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              {/* Tabela de Vulnerabilidades e Busca */}
              <section>
                <div className="mb-6 flex flex-col sm:flex-row justify-between items-end gap-4">
                  <div className="flex items-center gap-3 w-full sm:w-auto">
                    <div className="h-0.5 w-12 bg-emerald-900/50"></div>
                    <h2 className="text-xl font-bold text-red-500 uppercase tracking-[0.2em] drop-shadow-[0_0_8px_rgba(239,68,68,0.5)] whitespace-nowrap">AMEAÇAS ATIVAS</h2>
                    <div className="h-0.5 flex-grow bg-emerald-900/50 hidden sm:block"></div>
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
                    : `[ SISTEMA EXIBINDO AS ${vulns.length} VULNERABILIDADES MAIS RECENTES... ]`}
                </div>
                
                <div className="bg-black/50 border border-emerald-900/50 shadow-[0_0_30px_rgba(0,0,0,0.8)] overflow-hidden relative">
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-emerald-900/30">
                      <thead className="bg-emerald-950/20">
                        <tr>
                          <th className="py-4 pl-4 pr-3 text-left text-[11px] uppercase tracking-widest text-emerald-600 sm:pl-6">PONTUAÇÃO (SCORE)</th>
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
                              onClick={() => setSelectedVuln(vuln)}
                            >
                              <td className="whitespace-nowrap py-4 pl-4 pr-3 sm:pl-6 text-sm">
                                {getCustomScoreBadge(vuln.custom_risk_score)}
                              </td>
                              <td className="whitespace-nowrap py-4 px-3 text-sm font-bold text-emerald-500 group-hover:text-emerald-300">
                                {vuln.cve_id}
                              </td>
                              <td className="py-4 px-3 text-sm">
                                <div className="font-medium text-zinc-300 max-w-sm truncate uppercase group-hover:text-white" title={vuln.title}>{vuln.title}</div>
                                <div className="text-[10px] text-zinc-500 mt-1 tracking-widest">ALVO: {vuln.vendor} {vuln.product}</div>
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
            <div className="bg-zinc-950 border border-emerald-500/50 shadow-[0_0_40px_rgba(16,185,129,0.2)] w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col relative animate-in fade-in zoom-in-95 duration-200">
              
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
                  </div>
                </div>

                <div className="flex flex-col lg:flex-row gap-8">
                  
                  {/* Coluna Esquerda: IA */}
                  <div className="lg:w-3/5 flex flex-col gap-6">
                    <div className="border border-blue-500/30 bg-blue-950/10 p-5 relative overflow-hidden">
                      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-600 to-indigo-600"></div>
                      
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-5">
                        <div>
                          <h3 className="font-bold text-blue-400 flex items-center gap-2 uppercase tracking-wider text-sm">
                            <span className="animate-spin text-lg">⚙</span> MOTOR_DE_ANALISE_IA
                          </h3>
                          <p className="text-[10px] text-zinc-500 mt-1 uppercase tracking-widest">Executa roteiro de tradução com IA Gemini.</p>
                        </div>
                        
                        {/* Se o token estiver salvo, mostra o botão. Senão, mostra input */}
                        {isKeySaved ? (
                          !aiAnalysis && !isAiLoading && (
                            <div className="flex flex-col items-end gap-2">
                              <button 
                                onClick={() => handleAskAI(selectedVuln.cve_id)}
                                className="bg-black border border-blue-500 text-blue-400 hover:bg-blue-500 hover:text-black hover:shadow-[0_0_15px_rgba(59,130,246,0.6)] font-bold py-2 px-4 transition-all text-xs uppercase tracking-widest flex-shrink-0"
                              >
                                &gt;_ EXECUTAR_SIMPLIFICACAO.SH
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
                            <div className="flex justify-between items-center">
                              <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener noreferrer" className="text-[9px] text-blue-600 hover:text-blue-400 uppercase underline">
                                Obter Token Gratuito
                              </a>
                              <button onClick={saveApiKey} className="text-xs bg-blue-900/50 hover:bg-blue-600 border border-blue-500 text-blue-300 font-bold py-1 px-3 uppercase">
                                Salvar
                              </button>
                            </div>
                          </div>
                        )}
                      </div>

                      {isAiLoading && (
                        <div className="text-xs text-blue-400 font-mono flex flex-col gap-2">
                          <div><span className="text-zinc-500">[SISTEMA]</span> Autenticando Token...</div>
                          <div><span className="text-zinc-500">[SISTEMA]</span> Analisando vetores de vulnerabilidade...</div>
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
                          </div>
                          {aiAnalysis.split('\n').map((paragraph, idx) => (
                            <p key={idx} className="mb-3 font-sans opacity-90">{paragraph}</p>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Coluna Direita: Dados Brutos */}
                  <div className="lg:w-2/5 space-y-6">
                    <div className="border border-zinc-800 bg-zinc-900/50 p-4">
                      <h4 className="text-[10px] font-bold text-emerald-600 uppercase tracking-widest mb-3 border-b border-zinc-800 pb-2">
                        DESCRIÇÃO_TÉCNICA_BRUTA
                      </h4>
                      <p className="text-zinc-400 text-xs leading-relaxed font-sans">
                        {selectedVuln.description || 'N/A'}
                      </p>
                    </div>

                    <div className="border border-orange-500/30 bg-orange-950/20 p-4 relative">
                      <div className="absolute top-0 left-0 w-1 h-full bg-orange-500"></div>
                      <h4 className="text-[10px] font-bold text-orange-500 uppercase tracking-widest mb-3 border-b border-orange-900/50 pb-2">
                        AÇÃO_OBRIGATÓRIA_CISA
                      </h4>
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

                </div>
              </div>
            </div>
          </div>
        )}

        {/* MODAL NOTÍCIA (ADVISORY) */}
        {selectedAdvisory && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm transition-opacity">
            <div className="bg-zinc-950 border border-emerald-500/50 shadow-[0_0_40px_rgba(16,185,129,0.2)] w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col relative animate-in fade-in zoom-in-95 duration-200">
              
              <div className="bg-emerald-950/50 border-b border-emerald-900/50 p-2 flex justify-between items-center">
                <div className="flex gap-2 items-center px-2">
                  <span className="text-emerald-500 font-bold text-xs uppercase animate-pulse">● FEED_DE_NOTÍCIAS</span>
                </div>
                <button 
                  onClick={closeModal}
                  className="text-emerald-500 hover:text-white hover:bg-emerald-700 px-3 py-1 text-xs font-bold transition-colors uppercase border border-transparent hover:border-emerald-400"
                >
                  [X] FECHAR
                </button>
              </div>

              <div className="overflow-y-auto p-6 sm:p-8 flex-grow cyber-scrollbar">
                
                <div className="mb-6 pb-4 border-b border-emerald-900/30">
                  <span className="text-[10px] uppercase tracking-widest text-zinc-400 bg-zinc-900 px-2 py-1 border border-zinc-800">
                    FONTE: <span className="text-emerald-500">{selectedAdvisory.vendor}</span>
                  </span>
                  <span className="text-[10px] text-zinc-500 ml-4">{formatDate(selectedAdvisory.published_at)}</span>
                  
                  <h2 className="text-xl font-bold text-white uppercase tracking-wide mt-4">{selectedAdvisory.title}</h2>
                </div>

                <div className="text-zinc-300 text-sm leading-relaxed prose prose-invert max-w-none font-sans">
                  <div dangerouslySetInnerHTML={{ __html: selectedAdvisory.description }} />
                </div>

                <div className="mt-8 pt-4 border-t border-emerald-900/30 flex justify-end">
                  <a 
                    href={selectedAdvisory.source_url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-[10px] text-emerald-600 hover:text-emerald-400 font-bold tracking-widest uppercase flex items-center gap-2"
                  >
                    ACESSAR_FONTE_ORIGINAL &gt;&gt;
                  </a>
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
