#!/bin/sh
set -e

echo "[entrypoint] aplicando migraciones..."
npx prisma migrate deploy

echo "[entrypoint] iniciando API..."
exec node dist/main.js
