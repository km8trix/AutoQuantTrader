# syntax=docker/dockerfile:1.7

FROM node:22-alpine AS development

ARG PNPM_VERSION=11.7.0
RUN corepack enable && corepack prepare "pnpm@${PNPM_VERSION}" --activate

WORKDIR /workspace/apps/web

COPY apps/web/package.json apps/web/pnpm-lock.yaml apps/web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY apps/web ./

EXPOSE 5173

CMD ["pnpm", "dev", "--host", "0.0.0.0"]
