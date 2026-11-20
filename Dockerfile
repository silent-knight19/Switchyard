FROM node:26.13.1-alpine AS builder

WORKDIR /app

RUN npm install -g pnpm@12.21.0

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/gateway/package.json apps/gateway/tsconfig*.json ./apps/gateway/
COPY apps/mock-upstream/package.json apps/mock-upstream/tsconfig.json ./apps/mock-upstream/
COPY apps/web/package.json apps/web/tsconfig.json ./apps/web/
COPY packages/shared/package.json packages/shared/tsconfig.json ./packages/shared/

RUN pnpm install --frozen-lockfile

COPY apps/gateway/src/ ./apps/gateway/src/
RUN pnpm --filter @switchyard/gateway build

FROM node:26.13.1-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

RUN npm install -g pnpm@12.21.0

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/gateway/package.json ./apps/gateway/
COPY apps/mock-upstream/package.json ./apps/mock-upstream/
COPY apps/web/package.json ./apps/web/
COPY packages/shared/package.json ./packages/shared/

RUN pnpm install --frozen-lockfile --prod

COPY --from=builder /app/apps/gateway/dist ./apps/gateway/dist

USER node

EXPOSE 3000

CMD ["node", "apps/gateway/dist/index.js"]
