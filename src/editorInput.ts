export type InputTrackerState = {
  line: string;
  escapeState: 0 | 1 | 2;
};

export type TrackedInput = InputTrackerState & {
  outgoing: string;
  targets: string[];
};

const EDITOR_COMMAND = /^(?:sudo\s+)?(?:nano|vim|vi)\b(.*)$/i;

export function extractEditorTarget(input: string): string | undefined {
  const match = input.trim().match(EDITOR_COMMAND);
  if (!match) return undefined;

  const args = tokenize(match[1]);
  const candidates = args.filter(arg => arg !== '--' && !arg.startsWith('-') && !arg.startsWith('+'));
  const target = candidates[candidates.length - 1];
  return target?.trim() || undefined;
}

export function normalizeRemoteEditorInput(input: string): string {
  return extractEditorTarget(input) ?? unquote(input.trim());
}

export function extractNanoPath(header: string): string | undefined {
  const match = header.trim().match(/\bGNU nano\s+\S+\s+(.+?)\s*$/i);
  return match?.[1].trim() || undefined;
}

export function trackExternalEditorInput(text: string, state: InputTrackerState): TrackedInput {
  let line = state.line;
  let escapeState = state.escapeState;
  let outgoing = '';
  const targets: string[] = [];

  for (const char of text) {
    outgoing += char;

    if (escapeState === 1) {
      escapeState = char === '[' ? 2 : 0;
      continue;
    }
    if (escapeState === 2) {
      if (char.charCodeAt(0) >= 0x40 && char.charCodeAt(0) <= 0x7e) escapeState = 0;
      continue;
    }
    if (char === '\x1b') {
      escapeState = 1;
      continue;
    }
    if (char === '\x7f' || char === '\x08') {
      line = line.slice(0, -1);
      continue;
    }
    if (char === '\x03' || char === '\x15') {
      line = '';
      continue;
    }
    if (char === '\x17') {
      line = line.replace(/\s*\S+\s*$/, '');
      continue;
    }
    if (char === '\r' || char === '\n') {
      const target = extractEditorTarget(line);
      line = '';
      if (target) {
        targets.push(target);
        outgoing = `${outgoing.slice(0, -1)}\x15\r`;
      }
      continue;
    }
    if (char.charCodeAt(0) >= 32) line += char;
  }

  return { line, escapeState, outgoing, targets };
}

function tokenize(value: string): string[] {
  return [...value.matchAll(/"((?:\\.|[^"])*)"|'([^']*)'|(\S+)/g)].map(match =>
    (match[1] ?? match[2] ?? match[3]).replace(/\\([\\"])/g, '$1'),
  );
}

function unquote(value: string): string {
  if (value.length >= 2 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
    return value.slice(1, -1);
  }
  return value;
}
