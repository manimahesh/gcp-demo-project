# OWASP Top 10 Interactive Security Demo - Dockerfile
# This Dockerfile creates a container to run the interactive Node.js demo application

# Use official Node.js LTS image
FROM node:18-alpine

# Metadata
LABEL maintainer="Security Education Team"
LABEL description="OWASP Top 10 Interactive Security Vulnerabilities Demo"
LABEL version="2.0"
LABEL warning="Contains intentional vulnerabilities - Educational use only!"

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy application files
COPY server.js ./
COPY public ./public

# Create non-root user for running the app
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Change ownership of app directory
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port 3000
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/api/users', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); })" || exit 1

# Environment variable for production
ENV NODE_ENV=production

# Start the application
CMD ["node", "server.js"]
