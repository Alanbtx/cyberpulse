// Prompt pronto para colar em QUALQUER chat de IA (inclusive a IA homologada da empresa).
// Montado no navegador com os dados já carregados: funciona mesmo com o servidor ou as IAs fora do ar.
//
// Mantém as MESMAS três seções e regras do prompt da plataforma (backend/app/ai.py → build_prompt),
// para a resposta sair no mesmo formato. Um teste do backend confere que as seções batem.

export interface PromptVuln {
  cve_id: string;
  title: string;
  description: string | null;
  vendor: string | null;
  product: string | null;
  severity: string | null;
  cvss_score: string | null;
  cvss_vector?: string | null;
  known_exploited?: boolean;
  ransomware_use?: boolean | null;
  epss_score?: number | null;
  cisa_date_added: string | null;
  cisa_required_action: string | null;
  cisa_due_date: string | null;
}

export const PROMPT_SECTIONS = [
  'O QUE É A VULNERABILIDADE',
  'COMO VERIFICAR SE VOCÊ ESTÁ VULNERÁVEL',
  'PLANO DE AÇÃO',
] as const;

const nd = (v: string | null | undefined) => (v && String(v).trim() ? String(v).trim() : 'N/D');

function date(v: string | null | undefined): string {
  if (!v) return 'N/D';
  const d = new Date(v.length === 10 ? `${v}T00:00:00` : v);
  return Number.isNaN(d.getTime()) ? v : d.toLocaleDateString('pt-BR');
}

export function buildPrompt(v: PromptVuln): string {
  const cve = v.cve_id;
  const exploited = v.known_exploited === false ? 'NÃO / DESCONHECIDO' : 'SIM (catálogo CISA KEV)';
  const ransomware = v.ransomware_use ? 'SIM' : 'NÃO / DESCONHECIDO';
  const epss = v.epss_score != null ? `${(v.epss_score * 100).toFixed(1).replace('.', ',')}%` : 'N/D';
  const cvss = v.cvss_score ? `${v.cvss_score} (${nd(v.severity)})${v.cvss_vector ? ` ${v.cvss_vector}` : ''}` : 'ainda não publicado pelo NVD';

  return `Você é um sistema de Inteligência de Ameaças focado em simplificar problemas complexos de segurança para pessoas leigas e fornecer ações extremamente diretas.

Se você tiver acesso à internet, pesquise este CVE nas fontes oficiais listadas abaixo (e no site do fabricante) para confirmar KBs, versões afetadas e correções, e cite os links que usar.

DADOS DA VULNERABILIDADE (fonte: CyberPulse, com dados da CISA KEV, NVD e FIRST EPSS):
- CVE: ${cve}
- Fabricante / Produto: ${nd(v.vendor)} / ${nd(v.product)}
- Título: ${nd(v.title)}
- Descrição: ${nd(v.description)}
- Ação exigida pela CISA: ${nd(v.cisa_required_action)}
- Na lista da CISA desde: ${date(v.cisa_date_added)} | Prazo da CISA para corrigir: ${date(v.cisa_due_date)}
- CVSS: ${cvss}
- Sendo explorada ativamente: ${exploited}
- Usada em campanhas de ransomware: ${ransomware}
- Probabilidade de exploração nos próximos 30 dias (EPSS): ${epss}
- Fontes oficiais:
  - https://nvd.nist.gov/vuln/detail/${cve}
  - https://www.cve.org/CVERecord?id=${cve}
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cve}

Explique de forma extremamente simples, didática e acessível (como para um leigo), sem jargões confusos. Responda ESTRITAMENTE no formato abaixo. Use apenas **Texto** para os títulos:

**${PROMPT_SECTIONS[0]}**
[OBRIGATÓRIO: na primeira frase, diga de forma destacada se a falha já está sendo explorada ativamente (campo "Sendo explorada ativamente"). Depois explique a falha com uma analogia simples e o impacto.]

**${PROMPT_SECTIONS[1]}**
[Passo a passo prático com comandos reais e específicos para o produto/fabricante/SO, em blocos de código.
Se for Windows, liste os números de KB da Microsoft que corrigem a falha e ensine o comando (ex: Get-HotFix).
Se for Linux, software ou biblioteca, liste as versões vulneráveis e corrigidas e o comando para descobrir a versão instalada.
Se não conseguir confirmar um número exato de KB ou versão, diga claramente que não foi confirmado em vez de inventar.]

**${PROMPT_SECTIONS[2]}**
[A ação da CISA ou a mitigação técnica em passos numerados e práticos, incluindo o prazo da CISA quando houver.]

REGRAS:
- Responda em Português do Brasil.
- Não adivinhe a profissão do leitor e não use tratamentos ("analista", "amigo" etc).
- Sem saudações ou despedidas.
- Use listas com "-" ou números quando houver vários itens.
- Os títulos devem ser EXATAMENTE os três acima, em maiúsculas e entre **.`;
}

/** Copia texto para a área de transferência. Devolve false se o navegador bloquear. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* tenta o método antigo abaixo */
  }
  try {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(area);
    return ok;
  } catch {
    return false;
  }
}
