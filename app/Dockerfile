FROM node:18 AS builder
WORKDIR /usr/src/app

# Copy only package manifest first to leverage layer caching
COPY app/package.json ./package.json
RUN npm install
RUN npm ci --only=production

# Copy app sources
COPY app/ .

FROM node:18-slim
WORKDIR /usr/src/app
COPY --from=builder /usr/src/app /usr/src/app
EXPOSE 8080
ENV PORT=8080
CMD ["node", "server.js"]
