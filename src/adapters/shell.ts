import { spawn } from 'node:child_process';

export interface RunOptions {
  cwd: string;
  env?: Record<string, string>;
  timeoutMs?: number;
}

export interface RunResult {
  command: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

/** The only way this tool executes external programs. Tests substitute FakeShell. */
export interface Shell {
  run(cmd: string, args: string[], opts: RunOptions): Promise<RunResult>;
}

const SECRET_KEY_PATTERN = /(KEY|TOKEN|SECRET|PASSWORD|RPC|MNEMONIC|AUTH)/i;

/** Collect secret-looking values from an environment so they can be scrubbed from output. */
export function secretValues(env: NodeJS.ProcessEnv): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(env)) {
    if (v && v.length >= 8 && SECRET_KEY_PATTERN.test(k)) out.push(v);
  }
  return out;
}

/**
 * Remove known secret values, credentials embedded in URLs and 0x-prefixed 32-byte hex strings
 * (private-key shaped) from text before it is stored or printed.
 */
export function redact(text: string, secrets: string[] = []): string {
  let out = text;
  for (const s of secrets) out = out.split(s).join('[REDACTED]');
  out = out.replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+(:[^\s/@]*)?@/gi, '$1[REDACTED]@');
  out = out.replace(
    /\b(https?|wss?):\/\/[^\s"']*(rpc|infura|alchemy|quicknode|ankr)[^\s"']*/gi,
    '[REDACTED_RPC_URL]',
  );
  out = out.replace(/\b0x[0-9a-fA-F]{64}\b/g, '[REDACTED_HEX32]');
  return out;
}

export function formatCommand(cmd: string, args: string[]): string {
  return [cmd, ...args].map((a) => (/^[\w@%+=:,./-]+$/.test(a) ? a : JSON.stringify(a))).join(' ');
}

export class RealShell implements Shell {
  private readonly secrets: string[];
  constructor(env: NodeJS.ProcessEnv = process.env) {
    this.secrets = secretValues(env);
  }

  run(cmd: string, args: string[], opts: RunOptions): Promise<RunResult> {
    const command = formatCommand(cmd, args);
    return new Promise((resolve) => {
      const child = spawn(cmd, args, {
        cwd: opts.cwd,
        env: { ...process.env, ...opts.env },
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      const timer = opts.timeoutMs
        ? setTimeout(() => {
            timedOut = true;
            child.kill('SIGKILL');
          }, opts.timeoutMs)
        : undefined;
      child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
      child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
      child.on('error', (err) => {
        if (timer) clearTimeout(timer);
        resolve({
          command,
          exitCode: 127,
          stdout: '',
          stderr: redact(`failed to start '${cmd}': ${err.message}`, this.secrets),
          timedOut: false,
        });
      });
      child.on('close', (code) => {
        if (timer) clearTimeout(timer);
        resolve({
          command,
          exitCode: code ?? 1,
          stdout: redact(stdout, this.secrets),
          stderr: redact(stderr, this.secrets),
          timedOut,
        });
      });
    });
  }
}

export type FakeHandler = (
  cmd: string,
  args: string[],
  opts: RunOptions,
) => Partial<RunResult> | undefined;

/** Test double: records calls, answers from a handler. Unhandled commands fail loudly. */
export class FakeShell implements Shell {
  readonly calls: { cmd: string; args: string[]; cwd: string; env?: Record<string, string> }[] = [];
  constructor(private readonly handler: FakeHandler) {}

  async run(cmd: string, args: string[], opts: RunOptions): Promise<RunResult> {
    this.calls.push({ cmd, args, cwd: opts.cwd, env: opts.env });
    const r = this.handler(cmd, args, opts);
    if (!r) throw new Error(`FakeShell: unexpected command: ${formatCommand(cmd, args)}`);
    return {
      command: formatCommand(cmd, args),
      exitCode: 0,
      stdout: '',
      stderr: '',
      timedOut: false,
      ...r,
    };
  }
}
