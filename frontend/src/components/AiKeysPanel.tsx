import { useState } from 'react';
import type { AiKeys, Provider } from '../aiKeys';
import { PROVIDERS, maskKey } from '../aiKeys';

interface Props {
  keys: AiKeys;
  remember: boolean;
  onRememberChange: (remember: boolean) => void;
  onSave: (provider: Provider, key: string) => string | null; // devolve mensagem de erro ou null
  onRemove: (provider: Provider) => void;
  highlight?: Provider | null; // destaca a chave que deu erro
}

function KeySlot({ provider, value, onSave, onRemove, highlight }: {
  provider: Provider;
  value: string;
  onSave: Props['onSave'];
  onRemove: Props['onRemove'];
  highlight: boolean;
}) {
  const info = PROVIDERS[provider];
  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  const save = () => {
    const err = onSave(provider, draft.trim());
    setError(err);
    if (!err) {
      setDraft('');
      setEditing(false);
    }
  };

  const border = highlight ? 'border-red-600' : value ? 'border-emerald-800' : 'border-blue-900/60';

  return (
    <div className={`border ${border} bg-black/40 p-3 flex flex-col gap-2`}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-bold text-blue-300 uppercase tracking-wider">{info.label}</span>
        <span className="text-[9px] text-zinc-500 uppercase tracking-wider">{info.tag}</span>
      </div>

      {value && !editing ? (
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] text-emerald-400 font-mono">✓ {maskKey(value)}</span>
          <span className="flex gap-3">
            <button type="button" onClick={() => setEditing(true)} className="text-[9px] text-zinc-500 hover:text-blue-300 uppercase underline">Trocar</button>
            <button type="button" onClick={() => onRemove(provider)} className="text-[9px] text-zinc-500 hover:text-red-400 uppercase underline">Remover</button>
          </span>
        </div>
      ) : (
        <>
          <div className="flex gap-2">
            <input
              type="password"
              value={draft}
              onChange={e => setDraft(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') save(); }}
              placeholder={info.placeholder}
              aria-label={`Chave do ${info.label}`}
              autoComplete="off"
              spellCheck={false}
              className="flex-1 min-w-0 bg-black border border-blue-800 text-blue-300 p-1.5 text-xs font-mono focus:outline-none focus:border-blue-400"
            />
            <button type="button" onClick={save} className="text-[10px] bg-blue-900/50 hover:bg-blue-600 border border-blue-500 text-blue-200 font-bold px-3 uppercase">
              Salvar
            </button>
          </div>
          {error && <span className="text-[10px] text-red-400">{error}</span>}
        </>
      )}

      <div className="flex flex-wrap gap-x-4 gap-y-1">
        <a href={info.createUrl} target="_blank" rel="noopener noreferrer" className="text-[10px] text-blue-500 hover:text-blue-300 uppercase underline">
          {info.createLabel} ↗
        </a>
        {info.extraUrl && (
          <a href={info.extraUrl} target="_blank" rel="noopener noreferrer" className="text-[10px] text-blue-500 hover:text-blue-300 uppercase underline">
            {info.extraLabel} ↗
          </a>
        )}
      </div>
    </div>
  );
}

export default function AiKeysPanel({ keys, remember, onRememberChange, onSave, onRemove, highlight }: Props) {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        {(Object.keys(PROVIDERS) as Provider[]).map(p => (
          <KeySlot key={p} provider={p} value={keys[p]} onSave={onSave} onRemove={onRemove} highlight={highlight === p} />
        ))}
      </div>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <p className="text-[10px] text-zinc-500 leading-relaxed">
          As duas são gratuitas e você pode usar uma ou as duas. Com as duas, se o Gemini estiver sobrecarregado,
          o OpenRouter assume na hora com modelos gratuitos. As chaves ficam só no seu navegador.
        </p>
        <label className="flex items-center gap-2 text-[10px] text-zinc-500 uppercase tracking-wider cursor-pointer whitespace-nowrap">
          <input type="checkbox" checked={remember} onChange={e => onRememberChange(e.target.checked)} className="accent-blue-500" />
          Lembrar neste navegador
        </label>
      </div>
    </div>
  );
}
