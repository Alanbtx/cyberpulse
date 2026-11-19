import { PAGE_SIZES } from '../filters';

interface Props {
  page: number;
  pages: number;
  pageSize: number;
  total: number;
  disabled?: boolean;
  onPage: (page: number) => void;
  onPageSize: (size: number) => void;
}

const btn = 'text-[10px] px-3 py-1.5 uppercase tracking-widest border border-emerald-800 bg-black text-emerald-500 hover:bg-emerald-500 hover:text-black transition-colors disabled:opacity-30 disabled:pointer-events-none';

export default function Pagination({ page, pages, pageSize, total, disabled, onPage, onPageSize }: Props) {
  if (total === 0) return null;
  const from = (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);

  return (
    <nav className="mt-4 flex flex-col sm:flex-row items-center justify-between gap-3" aria-label="Paginação">
      <div className="text-[10px] tracking-widest text-emerald-700 uppercase">
        EXIBINDO {from}–{to} DE {total}
      </div>

      <div className="flex items-center gap-2">
        <button type="button" className={btn} disabled={disabled || page <= 1} onClick={() => onPage(1)} aria-label="Primeira página">«</button>
        <button type="button" className={btn} disabled={disabled || page <= 1} onClick={() => onPage(page - 1)}>&lt; ANTERIOR</button>
        <span className="text-[10px] tracking-widest text-emerald-400 px-2 whitespace-nowrap">
          PÁG {page} / {pages}
        </span>
        <button type="button" className={btn} disabled={disabled || page >= pages} onClick={() => onPage(page + 1)}>PRÓXIMA &gt;</button>
        <button type="button" className={btn} disabled={disabled || page >= pages} onClick={() => onPage(pages)} aria-label="Última página">»</button>
      </div>

      <label className="text-[10px] tracking-widest text-emerald-700 uppercase flex items-center gap-2">
        POR PÁGINA
        <select
          value={pageSize}
          disabled={disabled}
          onChange={e => onPageSize(Number(e.target.value))}
          className="bg-black border border-emerald-900/50 text-emerald-400 text-[10px] px-2 py-1 focus:outline-none focus:border-emerald-500"
        >
          {PAGE_SIZES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </label>
    </nav>
  );
}
