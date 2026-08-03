# Unified dashboard (Next.js 16) — operations and investigation console.
# Uses Next.js standalone output for a small runtime image.

FROM node:22-slim AS build
WORKDIR /app
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard .
RUN npm run build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0
COPY --chown=node:node --from=build /app/public ./public
COPY --chown=node:node --from=build /app/.next/standalone ./
COPY --chown=node:node --from=build /app/.next/static ./.next/static
COPY --chown=node:node dashboard/scripts ./scripts
COPY --chown=node:node supabase/migrations /app/supabase/migrations
EXPOSE 3000
USER node
CMD ["node", "server.js"]
