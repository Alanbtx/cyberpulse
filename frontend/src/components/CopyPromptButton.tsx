import { useEffect, useRef, useState } from 'react';
import type { PromptVuln } from '../prompt';
import { buildPrompt, copyText } from '../prompt';

interface Props {
  vuln: PromptVuln;
  variant?: 'compact' | 'full';
}

export default function CopyPromptButton({ vuln, variant = 'full' }: Props) {
  const [state, setState] = useState<'idle' | 'copied'>('idle');
  const [manual, setManual] = useState<string | null>(null);
  const areaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (state !== 'copied') return;
    const t = setTimeout(() => setState('idle'), 2500);
    return () => clearTimeout(t);
  }, [state]);

  useEffect(() => {
    if (manual) areaRef.current?.select();
  }, [manual]);

  const copy = async (e: React.MouseEvent) => {
    e.stopPropagation(); // não abre o modal quando clicado na linha da tabela
    const prompt = buildPrompt(vuln);
    if (await copyText(prompt)) setState('copied');
    else setManual(prompt); // navegador bloqueou: mostra o texto para copiar à mão
  };

  const label = state === 'copied'
    ? '✓ COPIADO'
    : variant === 'compact' ? '⧉ PROMPT' : '⧉ COPIAR PROMPT PARA OUTRA IA';

  return (
    <>
      <button
        type="button"
        onClick={copy}
        title="Copia um prompt pronto com os dados desta CVE para colar em qualquer chat de IA"
        aria-label={`Copiar prompt da ${vuln.cve_id} para usar em outra IA`}
        className={variant === 'compact'
          ? `font-bold text-[10px] border px-3 py-1.5 uppercase tracking-widest transition-all ${state === 'copied' ? 'border-emerald-400 text-emerald-300 bg-emerald-950/60' : 'border-zinc-700 text-zinc-400 bg-black hover:border-blue-500 hover:text-blue-300'}`
          : `font-bold text-[11px] border px-4 py-2 uppercase tracking-widest transition-all ${state === 'copied' ? 'border-emerald-400 text-emerald-300 bg-emerald-950/60' : 'border-zinc-600 text-zinc-300 bg-black hover:border-blue-400 hover:text-blue-300'}`}
      >
        {label}
      </button>

      {manual && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/80 p-4"
          onClick={e => { e.stopPropagation(); setManual(null); }}
          role="dialog"
          aria-modal="true"
          aria-label="Copiar prompt manualmente"
        >
          <div className="w-full max-w-2xl border border-blue-500/50 bg-zinc-950 p-4 flex flex-col gap-3" onClick={e => e.stopPropagation()}>
            <p className="text-xs text-zinc-300">
              O navegador bloqueou a cópia automática. O texto já está selecionado: pressione <b>Ctrl+C</b> (ou <b>Cmd+C</b>) e cole no chat da IA.
            </p>
            <textarea ref={areaRef} readOnly value={manual} className="h-72 w-full bg-black border border-zinc-700 text-zinc-300 text-xs font-mono p-2" />
            <button type="button" onClick={() => setManual(null)} className="self-end text-xs border border-zinc-600 px-3 py-1 text-zinc-300 hover:border-blue-400">
              FECHAR
            </button>
          </div>
        </div>
      )}
    </>
  );
}
