FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci --silent
COPY src ./src
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
# Non-root user (uid/gid 10001) — keeps the CLI image consistent with the
# backend services. No HEALTHCHECK: the CLI has no HTTP endpoint.
RUN addgroup -g 10001 -S appuser \
 && adduser  -S -u 10001 -G appuser appuser
COPY package*.json ./
# --ignore-scripts: no transitive dep can run a lifecycle hook in the runner image.
RUN npm ci --omit=dev --ignore-scripts --silent
COPY --from=builder /app/dist ./dist
RUN chown -R 10001:10001 /app
USER appuser
ENTRYPOINT ["node", "dist/index.js"]
