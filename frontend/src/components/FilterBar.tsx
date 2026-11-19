import type { Facets, Filters, Severity, SortKey } from '../filters';
import { SEVERITIES, hasActiveFilters } from '../filters';

interface Props {
  filters: Filters;
  facets: Facets | null;
  onChange: (patch: Partial<Filters>) => void;
  onReset: () => void;
}

const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: 'CRÍTICO',
  HIGH: 'ALTO',
  MEDIUM: 'MÉDIO',
  LOW: 'BAIXO',
  PENDING: 'PENDENTE',
};

const SEVERITY_ACTIVE: Record<Severity, string> = {
  CRITICAL: 'border-red-500 bg-red-950/40 text-red-400',
  HIGH: 'border-orange-500 bg-orange-950/40 text-orange-400',
  MEDIUM: 'border-yellow-500 bg-yellow-950/40 text-yellow-400',
  LOW: 'border-emerald-500 bg-emerald-950/40 text-emerald-400',
  PENDING: 'border-zinc-400 bg-zinc-800/60 text-zinc-300',
};

const SORT_LABEL: Record<SortKey, string> = {
  score: 'CRITICIDADE',
  recent: 'CISA_RECENTES',
  epss: 'PROB_EXPLORAÇÃO',
  due: 'PRAZO_CISA',
};

const chip = 'text-[10px] px-2 py-1 uppercase tracking-widest border transition-colors whitespace-nowrap';
const idle = 'border-emerald-900/50 text-emerald-700 hover:text-emerald-400 hover:border-emerald-700';
const active = 'border-emerald-500 bg-emerald-950/50 text-emerald-400 font-bold';

function count(n: number | undefined) {
  return n === undefined ? '' : ` (${n})`;
}

export default function FilterBar({ filters, facets, onChange, onReset }: Props) {
  const toggleSeverity = (s: Severity) => {
    const next = filters.severities.includes(s)
      ? filters.severities.filter(x => x !== s)
      : [...filters.severities, s];
    onChange({ severities: next });
  };

  const vendorInList = !filters.vendor || facets?.vendors.some(v => v.name === filters.vendor);

  return (
    <div className="mb-4 border border-emerald-900/40 bg-black/40 p-3 flex flex-col gap-3" role="group" aria-label="Filtros">
      {/* Ordenação */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] text-emerald-700 tracking-widest w-24">ORDENAR:</span>
        {(Object.keys(SORT_LABEL) as SortKey[]).map(s => (
          <button
            key={s}
            type="button"
            aria-pressed={filters.sort === s}
            onClick={() => onChange({ sort: s })}
            className={`${chip} ${filters.sort === s ? active : idle}`}
          >
            {SORT_LABEL[s]}
          </button>
        ))}
      </div>

      {/* Severidade */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] text-emerald-700 tracking-widest w-24">SEVERIDADE:</span>
        {SEVERITIES.map(s => (
          <button
            key={s}
            type="button"
            aria-pressed={filters.severities.includes(s)}
            onClick={() => toggleSeverity(s)}
            className={`${chip} ${filters.severities.includes(s) ? SEVERITY_ACTIVE[s] + ' font-bold' : idle}`}
          >
            {SEVERITY_LABEL[s]}{count(facets?.severities[s])}
          </button>
        ))}
      </div>

      {/* Atalhos + fabricante + nota mínima */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] text-emerald-700 tracking-widest w-24">FILTRAR:</span>
        <button
          type="button"
          aria-pressed={filters.ransomware}
          onClick={() => onChange({ ransomware: !filters.ransomware })}
          className={`${chip} ${filters.ransomware ? 'border-red-500 bg-red-950/40 text-red-400 font-bold' : idle}`}
        >
          RANSOMWARE{count(facets?.ransomware)}
        </button>
        <button
          type="button"
          aria-pressed={filters.dueSoon}
          onClick={() => onChange({ dueSoon: !filters.dueSoon })}
          className={`${chip} ${filters.dueSoon ? 'border-orange-500 bg-orange-950/40 text-orange-400 font-bold' : idle}`}
          title="Prazo da CISA para corrigir vence nos próximos 14 dias"
        >
          PRAZO ≤ 14 DIAS{count(facets?.due_14_days)}
        </button>
        <button
          type="button"
          aria-pressed={filters.addedRecent}
          onClick={() => onChange({ addedRecent: !filters.addedRecent })}
          className={`${chip} ${filters.addedRecent ? active : idle}`}
          title="Adicionadas ao catálogo da CISA nos últimos 30 dias"
        >
          NOVAS 30 DIAS{count(facets?.added_30_days)}
        </button>

        <label className="flex items-center gap-1 text-[10px] text-emerald-700 tracking-widest">
          <span className="sr-only">Fabricante</span>
          <select
            value={filters.vendor}
            onChange={e => onChange({ vendor: e.target.value })}
            className="bg-black border border-emerald-900/50 text-emerald-400 text-[10px] uppercase tracking-widest px-2 py-1 max-w-[14rem] focus:outline-none focus:border-emerald-500"
          >
            <option value="">TODOS OS FABRICANTES</option>
            {!vendorInList && <option value={filters.vendor}>{filters.vendor}</option>}
            {facets?.vendors.map(v => (
              <option key={v.name} value={v.name}>{v.name} ({v.count})</option>
            ))}
          </select>
        </label>

        <label className="flex items-center gap-1 text-[10px] text-emerald-700 tracking-widest">
          <span className="sr-only">Nota mínima</span>
          <select
            value={filters.minScore ?? ''}
            onChange={e => onChange({ minScore: e.target.value === '' ? null : Number(e.target.value) })}
            className="bg-black border border-emerald-900/50 text-emerald-400 text-[10px] uppercase tracking-widest px-2 py-1 focus:outline-none focus:border-emerald-500"
          >
            <option value="">QUALQUER NOTA</option>
            <option value="5">NOTA ≥ 5</option>
            <option value="6.5">NOTA ≥ 6.5</option>
            <option value="8">NOTA ≥ 8</option>
          </select>
        </label>

        {hasActiveFilters(filters) && (
          <button
            type="button"
            onClick={onReset}
            className="text-[10px] px-2 py-1 uppercase tracking-widest text-zinc-500 hover:text-red-400 underline ml-auto"
          >
            LIMPAR FILTROS
          </button>
        )}
      </div>
      {filters.sort === 'due' && (
        <p className="text-[9px] text-zinc-600 tracking-widest">PRAZO_CISA: PRAZOS MAIS ANTIGOS PRIMEIRO (INCLUI VENCIDOS). COMBINE COM "PRAZO ≤ 14 DIAS" PARA VER SÓ OS PRÓXIMOS.</p>
      )}
    </div>
  );
}
