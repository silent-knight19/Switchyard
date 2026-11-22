FROM node:26.13.1-alpine AS builder

WORKDIR /app

RUN npm install -g pnpm@12.21.0

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/gateway/package.json apps/gateway/tsconfig*.json ./apps/gateway/
COPY apps/mock-upstream/package.json apps/mock-upstream/tsconfig*.json ./apps/mock-upstream/
COPY apps/web/package.json apps/web/tsconfig.json ./apps/web/
COPY packages/shared/package.json packages/shared/tsconfig.json ./packages/shared/

RUN pnpm install --frozen-lockfile

COPY apps/mock-upstream/src/ ./apps/mock-upstream/src/
RUN pnpm --filter @switchyard/mock-upstream build

FROM node:26.13.1-alpine AS runner

WORKDIR /app

ENV NODE_ENV=development

RUN npm install -g pnpm@12.21.0

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/gateway/package.json ./apps/gateway/
COPY apps/mock-upstream/package.json ./apps/mock-upstream/
COPY apps/web/package.json ./apps/web/
COPY packages/shared/package.json ./packages/shared/

RUN pnpm install --frozen-lockfile

COPY --from=builder /app/apps/mock-upstream/dist ./apps/mock-upstream/dist

USER node

EXPOSE 4000

CMD ["node", "apps/mock-upstream/dist/index.js"]
