# NetShield Node.js Backend Microservice Dockerfile
# Production-ready slim deployment container

FROM node:20-slim

ENV NODE_ENV=production
ENV PORT=5000

WORKDIR /app

# Copy dependency manifests and install production dependencies only
COPY package*.json ./
RUN npm ci --only=production --ignore-scripts

# Copy backend application source code
COPY src/ ./src/

# Security: Run as non-privileged system user 'node'
USER node

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:5000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))" || exit 1

CMD ["node", "src/server.js"]
