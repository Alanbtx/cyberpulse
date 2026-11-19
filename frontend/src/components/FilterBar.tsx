import { useState } from 'react';
import type { Facets, Filters, Severity, SortKey } from '../filters';
import { SEVERITIES } from '../filters';

interface Props {
  filters: Filters;
  facets: Facets | null;
  onChange: (patch: Partial<Filters>) => void;
  onReset: () => void;
}

const SORT_LABEL: Record<SortKey, string> = {
  score: 'Mais críticas',
  epss: 'Maior chance de ataque',
  recent: 'Incluídas recentemente',
  due: 'Prazo de correção mais próximo',
};

const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: 'Crítico',
  HIGH: 'Alto',
  MEDIUM: 'Médio',
  LOW: 'Baixo',
  PENDING: 'Sem nota ainda',
};

const SEVERITY_ACTIVE: Record<Severity, string> = {
  CRITICAL: 'border-red-500 bg-red-950/40 text-red-400',
  HIGH: 'border-orange-500 bg-orange-950/40 text-orange-400',
  MEDIUM: 'border-yellow-500 bg-yellow-950/40 text-yellow-400',
  LOW: 'border-emerald-500 bg-emerald-950/40 text-emerald-400',
  PENDING: 'border-zinc-400 bg-zinc-800/60 text-zinc-300',
};

const MIN_SCORES = [
  { value: 5, label: '5 ou mais' },
  { value: 6.5, label: '6,5 ou mais' },
  { value: 8, label: '8 ou mais (urgente)' },
];

const control = 'bg-black border border-emerald-900/60 text-emerald-400 text-[11px] uppercase tracking-wider px-2 py-1.5 focus:outline-none focus:border-emerald-500';
const legend = 'text-[10px] text-emerald-700 uppercase tracking-widest mb-2';

function n(value: number | undefined) {
  return value === undefined ? '' : ` (${value})`;
}

interface Pill {
  key: string;
  label: string;
  remove: () => void;
}

export default function FilterBar({ filters, facets, onChange, onReset }: Props) {
  const [open, setOpen] = useState(false);

  const pills: Pill[] = [
    ...(filters.q ? [{ key: 'q', label: `Busca: ${filters.q}`, remove: () => onChange({ q: '' }) }] : []),
    ...filters.severities.map(s => ({
      key: `sev-${s}`,
      label: SEVERITY_LABEL[s],
      remove: () => onChange({ severities: filters.severities.filter(x => x !== s) }),
    })),
    ...(filters.vendor ? [{ key: 'vendor', label: filters.vendor, remove: () => onChange({ vendor: '' }) }] : []),
    ...(filters.ransomware ? [{ key: 'ransom', label: 'Usada por ransomware', remove: () => onChange({ ransomware: false }) }] : []),
    ...(filters.dueSoon ? [{ key: 'due', label: 'Prazo em até 14 dias', remove: () => onChange({ dueSoon: false }) }] : []),
    ...(filters.addedRecent ? [{ key: 'new', label: 'Novas (30 dias)', remove: () => onChange({ addedRecent: false }) }] : []),
    ...(filters.minScore !== null
      ? [{ key: 'score', label: `Nota ≥ ${String(filters.minScore).replace('.', ',')}`, remove: () => onChange({ minScore: null }) }]
      : []),
  ];
  const panelFilters = pills.filter(p => p.key !== 'q').length;

  const toggleSeverity = (s: Severity) =>
    onChange({
      severities: filters.severities.includes(s)
        ? filters.severities.filter(x => x !== s)
        : [...filters.severities, s],
    });

  const vendorInList = !filters.vendor || facets?.vendors.some(v => v.name === filters.vendor);

  return (
    <div className="mb-4">
      <div className="flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-2 text-[10px] text-emerald-700 uppercase tracking-widest">
          Ordenar por
          <select value={filters.sort} onChange={e => onChange({ sort: e.target.value as SortKey })} className={control}>
            {(Object.keys(SORT_LABEL) as SortKey[]).map(s => (
              <option key={s} value={s}>{SORT_LABEL[s]}</option>
            ))}
          </select>
        </label>

        <button
          type="button"
          onClick={() => setOpen(o => !o)}
          aria-expanded={open}
          aria-controls="painel-filtros"
          className={`text-[11px] uppercase tracking-wider px-3 py-1.5 border transition-colors ${
            open || panelFilters
              ? 'border-emerald-500 text-emerald-300 bg-emerald-950/40'
              : 'border-emerald-900/60 text-emerald-500 hover:border-emerald-600'
          }`}
        >
          Filtros{panelFilters ? ` (${panelFilters})` : ''} {open ? '▴' : '▾'}
        </button>

        {pills.map(p => (
          <span key={p.key} className="inline-flex items-center gap-1 text-[10px] uppercase tracking-wider border border-emerald-800 text-emerald-300 bg-emerald-950/30 pl-2 pr-1 py-0.5">
            {p.label}
            <button type="button" onClick={p.remove} className="px-1 text-emerald-600 hover:text-red-400" aria-label={`Remover filtro ${p.label}`}>×</button>
          </span>
        ))}

        {pills.length > 1 && (
          <button type="button" onClick={onReset} className="text-[10px] uppercase tracking-wider text-zinc-500 hover:text-red-400 underline">
            Limpar tudo
          </button>
        )}
      </div>

      {open && (
        <div id="painel-filtros" className="mt-2 border border-emerald-900/40 bg-black/60 p-4 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          <fieldset>
            <legend className={legend}>Severidade (CVSS)</legend>
            <div className="flex flex-wrap gap-1.5">
              {SEVERITIES.map(s => {
                const on = filters.severities.includes(s);
                return (
                  <button
                    key={s}
                    type="button"
                    aria-pressed={on}
                    onClick={() => toggleSeverity(s)}
                    className={`text-[10px] uppercase tracking-wider px-2 py-1 border transition-colors ${
                      on ? `${SEVERITY_ACTIVE[s]} font-bold` : 'border-emerald-900/60 text-emerald-700 hover:text-emerald-400'
                    }`}
                  >
                    {SEVERITY_LABEL[s]}{n(facets?.severities[s])}
                  </button>
                );
              })}
            </div>
          </fieldset>

          <fieldset>
            <legend className={legend}>Fabricante</legend>
            <select value={filters.vendor} onChange={e => onChange({ vendor: e.target.value })} className={`${control} w-full`}>
              <option value="">Todos</option>
              {!vendorInList && <option value={filters.vendor}>{filters.vendor}</option>}
              {facets?.vendors.map(v => (
                <option key={v.name} value={v.name}>{v.name} ({v.count})</option>
              ))}
            </select>
          </fieldset>

          <fieldset>
            <legend className={legend}>Nota de risco mínima</legend>
            <select
              value={filters.minScore ?? ''}
              onChange={e => onChange({ minScore: e.target.value === '' ? null : Number(e.target.value) })}
              className={`${control} w-full`}
            >
              <option value="">Qualquer nota</option>
              {MIN_SCORES.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </fieldset>

          <fieldset className="flex flex-col gap-1.5">
            <legend className={legend}>Situação</legend>
            {[
              { key: 'ransomware' as const, label: 'Usada em ataques de ransomware', count: facets?.ransomware },
              { key: 'dueSoon' as const, label: 'Prazo da CISA vence em até 14 dias', count: facets?.due_14_days },
              { key: 'addedRecent' as const, label: 'Incluída nos últimos 30 dias', count: facets?.added_30_days },
            ].map(o => (
              <label key={o.key} className="flex items-center gap-2 text-[11px] text-zinc-400 cursor-pointer hover:text-emerald-300">
                <input
                  type="checkbox"
                  checked={filters[o.key]}
                  onChange={e => onChange({ [o.key]: e.target.checked })}
                  className="accent-emerald-500"
                />
                {o.label}{n(o.count)}
              </label>
            ))}
          </fieldset>
        </div>
      )}
    </div>
  );
}
