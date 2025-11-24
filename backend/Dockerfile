# Multi-stage Dockerfile: build native modules in a builder stage, copy artifacts to final image
# Use a Debian-based builder to simplify native module compilation
FROM node:18-bullseye-slim AS builder
WORKDIR /usr/src/app

# Install build dependencies for native modules
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    build-essential \
    libsqlite3-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy package files and install production deps, forcing sqlite3 to build from source
COPY backend/package.json backend/package-lock.json* ./
RUN npm install
RUN npm ci --production --silent --no-audit --no-fund --build-from-source=sqlite3

# Copy backend source and frontend static files into builder (so native modules are present)
COPY backend/ ./
COPY frontend/ /usr/src/frontend/

# Final image: copy runtime files only
FROM node:18-bullseye-slim
WORKDIR /usr/src/app

# Set production environment
ENV NODE_ENV=production

# Copy node_modules and app files from builder (built against glibc)
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app .
COPY --from=builder /usr/src/frontend /usr/src/frontend

EXPOSE 8080
CMD ["node", "server.js"]
