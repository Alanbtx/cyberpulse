// Estado dos filtros da tabela e conversão de/para a URL (links compartilháveis).

export type SortKey = 'score' | 'recent' | 'epss' | 'due';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PENDING';

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'PENDING'];
export const SORTS: SortKey[] = ['score', 'recent', 'epss', 'due'];
export const PAGE_SIZES = [25, 50, 100];

export interface Filters {
  q: string;
  vendor: string;
  severities: Severity[];
  ransomware: boolean;
  dueSoon: boolean;     // prazo CISA nos próximos 14 dias
  addedRecent: boolean; // adicionadas ao KEV nos últimos 30 dias
  minScore: number | null;
  sort: SortKey;
  page: number;
  pageSize: number;
}

export interface Facets {
  total: number;
  vendors: { name: string; count: number }[];
  severities: Record<Severity, number>;
  ransomware: number;
  due_14_days: number;
  added_30_days: number;
}

export const DEFAULT_FILTERS: Filters = {
  q: '',
  vendor: '',
  severities: [],
  ransomware: false,
  dueSoon: false,
  addedRecent: false,
  minScore: null,
  sort: 'score',
  page: 1,
  pageSize: 25,
};

export function hasActiveFilters(f: Filters): boolean {
  return Boolean(f.q || f.vendor || f.severities.length || f.ransomware || f.dueSoon || f.addedRecent || f.minScore !== null);
}

/** Parâmetros para GET /api/v1/vulnerabilities/search */
export function toApiParams(f: Filters): URLSearchParams {
  const p = new URLSearchParams({
    lang: 'pt-br',
    sort: f.sort,
    page: String(f.page),
    page_size: String(f.pageSize),
  });
  if (f.q.trim()) p.set('q', f.q.trim().slice(0, 100));
  if (f.vendor) p.set('vendor', f.vendor);
  if (f.severities.length) p.set('severity', f.severities.join(','));
  if (f.ransomware) p.set('ransomware', 'true');
  if (f.dueSoon) p.set('due_within_days', '14');
  if (f.addedRecent) p.set('added_within_days', '30');
  if (f.minScore !== null) p.set('min_score', String(f.minScore));
  return p;
}

/** Versão curta para a barra de endereço (só o que difere do padrão). */
export function toUrlParams(f: Filters): URLSearchParams {
  const p = new URLSearchParams();
  if (f.q.trim()) p.set('q', f.q.trim());
  if (f.vendor) p.set('vendor', f.vendor);
  if (f.severities.length) p.set('sev', f.severities.join(','));
  if (f.ransomware) p.set('ransomware', '1');
  if (f.dueSoon) p.set('prazo', '1');
  if (f.addedRecent) p.set('novas', '1');
  if (f.minScore !== null) p.set('nota', String(f.minScore));
  if (f.sort !== DEFAULT_FILTERS.sort) p.set('ordem', f.sort);
  if (f.page > 1) p.set('pagina', String(f.page));
  if (f.pageSize !== DEFAULT_FILTERS.pageSize) p.set('por', String(f.pageSize));
  return p;
}

export function fromUrlParams(search: string): Filters {
  const p = new URLSearchParams(search);
  const int = (v: string | null, min: number, max: number) => {
    const n = Number.parseInt(v ?? '', 10);
    return Number.isFinite(n) && n >= min && n <= max ? n : null;
  };
  const score = Number.parseFloat(p.get('nota') ?? '');
  const sort = p.get('ordem') as SortKey;
  const pageSize = int(p.get('por'), 1, 100);
  return {
    q: (p.get('q') ?? '').slice(0, 100),
    vendor: (p.get('vendor') ?? '').slice(0, 100),
    severities: (p.get('sev') ?? '')
      .split(',')
      .map(s => s.trim().toUpperCase())
      .filter((s): s is Severity => (SEVERITIES as string[]).includes(s)),
    ransomware: p.get('ransomware') === '1',
    dueSoon: p.get('prazo') === '1',
    addedRecent: p.get('novas') === '1',
    minScore: Number.isFinite(score) && score >= 0 && score <= 10 ? score : null,
    sort: SORTS.includes(sort) ? sort : DEFAULT_FILTERS.sort,
    page: int(p.get('pagina'), 1, 10_000) ?? 1,
    pageSize: pageSize && PAGE_SIZES.includes(pageSize) ? pageSize : DEFAULT_FILTERS.pageSize,
  };
}
