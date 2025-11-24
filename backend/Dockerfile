FROM node:18-alpine
WORKDIR /usr/src/app
# When building from the repository root, copy the backend package files from their folder.
COPY backend/package.json backend/package-lock.json* ./
RUN npm install --production
# Copy backend source into the image
COPY backend/ .
# Copy frontend static files into /usr/src/frontend so server.js can serve ../frontend
COPY frontend/ /usr/src/frontend/
EXPOSE 8080
CMD ["node", "server.js"]
