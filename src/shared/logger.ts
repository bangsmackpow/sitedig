export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

const ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100,
};

function currentLevel(env: Record<string, string | undefined> = process.env): LogLevel {
  const raw = (env.LOG_LEVEL ?? 'info').toLowerCase();
  return (['debug', 'info', 'warn', 'error', 'silent'] as LogLevel[]).includes(raw as LogLevel)
    ? (raw as LogLevel)
    : 'info';
}

function timestamp(): string {
  return new Date().toISOString();
}

export interface Logger {
  debug(msg: string, extra?: Record<string, unknown>): void;
  info(msg: string, extra?: Record<string, unknown>): void;
  warn(msg: string, extra?: Record<string, unknown>): void;
  error(msg: string, extra?: Record<string, unknown>): void;
}

export function createLogger(env: Record<string, string | undefined> = process.env): Logger {
  const level = currentLevel(env);

  function write(lvl: LogLevel, msg: string, extra?: Record<string, unknown>) {
    if (ORDER[lvl] < ORDER[level]) return;
    const line = extra
      ? `${timestamp()} [${lvl}] ${msg} ${JSON.stringify(extra)}`
      : `${timestamp()} [${lvl}] ${msg}`;
    if (lvl === 'error') {
      process.stderr.write(line + '\n');
    } else {
      process.stdout.write(line + '\n');
    }
  }

  return {
    debug: (m, e) => write('debug', m, e),
    info: (m, e) => write('info', m, e),
    warn: (m, e) => write('warn', m, e),
    error: (m, e) => write('error', m, e),
  };
}

export const logger = createLogger();
