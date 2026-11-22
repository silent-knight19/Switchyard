import { runSeedDev } from './seed-dev/run.js';

/**
 * Development-only demo account seeder entrypoint (SW-P1-B02).
 *
 * Invoked explicitly by a developer (`pnpm seed:dev` or the compiled Docker entrypoint). It never
 * starts the Gateway HTTP listener and never acquires the Gateway singleton advisory lock.
 */
export async function main(): Promise<number> {
  return runSeedDev({
    env: process.env,
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
    argv: process.argv.slice(2),
  });
}

function isDirectExecution(entry: string | undefined): boolean {
  if (entry === undefined) return false;
  return /(?:^|[/\\])seed-dev\.(?:ts|js)$/.test(entry);
}

if (isDirectExecution(process.argv[1])) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch(() => {
      process.stderr.write('Demo seeding failed: UNEXPECTED_ERROR\n');
      process.exitCode = 1;
    });
}
