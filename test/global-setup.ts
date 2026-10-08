import { spawnSync } from 'node:child_process';

/**
 * Aplica las migraciones a la base de datos de pruebas antes de ejecutar
 * la suite e2e.
 */
export default function globalSetup(): void {
  const databaseUrl =
    process.env['TEST_DATABASE_URL'] ??
    'postgresql://app:JQhWXsB241mubc1Wyyr4x9k5VffYFf-x@127.0.0.1:5433/login_service_test';

  const result = spawnSync('npx', ['prisma', 'migrate', 'deploy'], {
    cwd: process.cwd(),
    env: { ...process.env, DATABASE_URL: databaseUrl },
    stdio: 'inherit',
    encoding: 'utf8',
  });

  if (result.status !== 0) {
    throw new Error('No se pudieron aplicar las migraciones en la BD de tests');
  }
}
