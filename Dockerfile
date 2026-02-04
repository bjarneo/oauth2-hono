# Multi-stage Dockerfile for OAuth2 Server
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/server/package.json ./packages/server/
COPY prisma ./prisma/

RUN npm ci

COPY tsconfig.base.json ./
COPY packages/shared ./packages/shared/
COPY packages/server ./packages/server/

RUN npx prisma generate
RUN npm run build -w @oauth2-hono/shared
RUN npm run build -w @oauth2-hono/server

FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/server/package.json ./packages/server/
COPY prisma ./prisma/

RUN npm ci --omit=dev && npx prisma generate

COPY --from=builder /app/packages/shared/dist ./packages/shared/dist
COPY --from=builder /app/packages/server/dist ./packages/server/dist

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["node", "packages/server/dist/index.js"]
