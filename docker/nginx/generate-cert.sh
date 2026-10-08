#!/usr/bin/env bash
# Genera un certificado TLS autofirmado para DESARROLLO/DEMO.
# En producción se debe usar un certificado de una CA pública
# (Let's Encrypt, CA corporativa, etc.) - NIST CSF PR.DS / ID.AM.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$DIR"

if [ -f "$DIR/tls.crt" ] && [ -f "$DIR/tls.key" ]; then
  echo "Los certificados ya existen en $DIR - nada que hacer."
  exit 0
fi

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$DIR/tls.key" \
  -out "$DIR/tls.crt" \
  -days 825 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$DIR/tls.key"
echo "Certificado autofirmado generado en $DIR (válido 825 días)."
