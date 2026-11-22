FROM node:26.13.1-alpine AS builder

WORKDIR /app

RUN npm install -g pnpm@12.21.0

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/gateway/package.json apps/gateway/tsconfig*.json ./apps/gateway/
COPY apps/mock-upstream/package.json apps/mock-upstream/tsconfig*.json ./apps/mock-upstream/
COPY apps/web/package.json apps/web/tsconfig.json apps/web/next.config.mjs ./apps/web/
COPY packages/shared/package.json packages/shared/tsconfig.json ./packages/shared/

RUN pnpm install --frozen-lockfile

COPY apps/web/src/ ./apps/web/src/
RUN pnpm --filter @switchyard/web build

FROM node:26.13.1-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3001
ENV HOSTNAME="0.0.0.0"

COPY --from=builder /app/apps/web/.next/standalone ./
COPY --from=builder /app/apps/web/.next/static ./apps/web/.next/static

USER node

EXPOSE 3001

CMD ["node", "apps/web/server.js"]
