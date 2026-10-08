# Etapa 1: dependencias
FROM node:22-bookworm-slim AS deps
WORKDIR /app
ENV npm_config_update_notifier=false
COPY package.json package-lock.json ./
RUN npm ci

# Etapa 2: build
FROM deps AS build
WORKDIR /app
COPY . .
# `prisma generate` no conecta a la BD, pero prisma.config.ts exige la
# variable al cargarse y en build no hay .env (dockerignored).
ENV DATABASE_URL=postgresql://build@localhost:5432/build
RUN npx prisma generate && npm run build

# Etapa 3: runtime sin herramientas de build (superficie minima - PR.PS)
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV npm_config_update_notifier=false
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules/@prisma ./node_modules/@prisma
COPY --from=build /app/prisma ./prisma
COPY --from=build /app/prisma.config.ts ./
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown -R node:node /app
USER node
EXPOSE 3000
ENTRYPOINT ["/entrypoint.sh"]
