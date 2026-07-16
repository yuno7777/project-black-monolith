# Unified dashboard (Next.js 15) — real-time threat feed.
# Uses Next.js standalone output for a small runtime image.

FROM node:22-slim AS build
WORKDIR /app
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm install
COPY dashboard .
RUN npm run build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0
COPY --from=build /app/public ./public
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY dashboard/scripts ./scripts
COPY supabase/migrations /app/supabase/migrations
EXPOSE 3000
CMD ["sh", "-c", "node scripts/migrate.mjs && node server.js"]
