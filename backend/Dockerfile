# Multi-stage Dockerfile: build native modules in a builder stage, copy artifacts to final image
# Use a Debian-based builder to simplify native module compilation
# Builder stage: no native build deps needed since sqlite3 was removed
FROM node:18 AS builder
WORKDIR /usr/src/app

# Copy package files and install production deps
COPY backend/package.json backend/package-lock.json* ./
# Prefer npm ci when lockfile is present, fall back to npm install
RUN npm ci --production --silent --no-audit --no-fund || npm install --production --silent --no-audit --no-fund

# Copy backend source and frontend static files into builder (so native modules are present)
COPY backend/ ./
COPY frontend/ /usr/src/frontend/

# Final image: copy runtime files only
FROM node:18
WORKDIR /usr/src/app

# Set production environment
ENV NODE_ENV=production

# Copy node_modules and app files from builder (built against glibc)
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app .
COPY --from=builder /usr/src/frontend /usr/src/frontend

EXPOSE 8080
CMD ["node", "server.js"]
