// Chaves de IA do usuário. Ficam só no navegador: sessionStorage por padrão,
// localStorage se o usuário marcar "lembrar neste navegador".

export type Provider = 'gemini' | 'openrouter';

export interface AiKeys {
  gemini: string;
  openrouter: string;
}

export const PROVIDERS: Record<Provider, {
  label: string;
  tag: string;
  storageKey: string;
  createUrl: string;
  createLabel: string;
  extraUrl?: string;
  extraLabel?: string;
  placeholder: string;
  header: string;
}> = {
  gemini: {
    label: 'Google Gemini',
    tag: 'Principal • gratuito',
    storageKey: 'cyberpulse_gemini_key',
    createUrl: 'https://aistudio.google.com/app/apikey',
    createLabel: 'Gerar chave grátis',
    placeholder: 'AIza...',
    header: 'X-Gemini-Key',
  },
  openrouter: {
    label: 'OpenRouter',
    tag: 'Reserva • gratuito',
    storageKey: 'cyberpulse_openrouter_key',
    createUrl: 'https://openrouter.ai/settings/keys',
    createLabel: 'Gerar chave grátis',
    placeholder: 'sk-or-v1-...',
    header: 'X-OpenRouter-Key',
  },
};

export const EMPTY_KEYS: AiKeys = { gemini: '', openrouter: '' };

function safe<T>(fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch {
    return fallback; // storage bloqueado (modo privado, política do navegador...)
  }
}

export function loadKeys(): { keys: AiKeys; remembered: boolean } {
  const keys = { ...EMPTY_KEYS };
  let remembered = false;
  (Object.keys(PROVIDERS) as Provider[]).forEach(p => {
    const k = PROVIDERS[p].storageKey;
    const session = safe(() => sessionStorage.getItem(k), null);
    const local = safe(() => localStorage.getItem(k), null);
    keys[p] = session || local || '';
    if (!session && local) remembered = true;
  });
  return { keys, remembered };
}

export function saveKey(provider: Provider, key: string, remember: boolean) {
  const k = PROVIDERS[provider].storageKey;
  safe(() => {
    sessionStorage.removeItem(k);
    localStorage.removeItem(k);
    (remember ? localStorage : sessionStorage).setItem(k, key);
  }, undefined);
}

export function removeKey(provider: Provider) {
  const k = PROVIDERS[provider].storageKey;
  safe(() => {
    sessionStorage.removeItem(k);
    localStorage.removeItem(k);
  }, undefined);
}

export function keyHeaders(keys: AiKeys): Record<string, string> {
  const headers: Record<string, string> = {};
  (Object.keys(PROVIDERS) as Provider[]).forEach(p => {
    if (keys[p].trim()) headers[PROVIDERS[p].header] = keys[p].trim();
  });
  return headers;
}

export function hasAnyKey(keys: AiKeys): boolean {
  return Boolean(keys.gemini.trim() || keys.openrouter.trim());
}

/** Mascara a chave para exibição: "sk-or-v1-…a9F3". */
export function maskKey(key: string): string {
  return key.length <= 10 ? '••••' : `${key.slice(0, 6)}…${key.slice(-4)}`;
}
