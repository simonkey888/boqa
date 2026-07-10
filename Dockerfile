# BOQA v1.4.0 — Production Docker Image
# URGENT-3: Containerization for Northflank deployment
#
# Build:  docker build -t boqa:1.4.0 .
# Run:    docker run -p 7070:7070 boqa:1.4.0
#
# Default API key is BOQA123 (override with -e BOQA_API_KEY=<stronger-key>
# in production for better security).

FROM node:20-slim

# Default API key — accepts "BOQA123" out of the box.
# Override in production with: docker run -e BOQA_API_KEY=<stronger-key> ...
ENV BOQA_API_KEY=BOQA123
ENV BOQA_MODE=live
ENV BOQA_AUTO_ANALYZE=true
ENV HEADLESS=true

# Install Playwright Chromium dependencies
# These are required for headless browser execution
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libgbm1 \
    libasound2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libpango-1.0-0 \
    libcairo2 \
    libatspi2.0-0 \
    libxshmfence1 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r boqa && useradd -r -g boqa -d /app -s /sbin/nologin boqa

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm ci --production && \
    npx playwright install chromium

# Copy application source
COPY . .

# Create output directories with proper permissions
RUN mkdir -p /app/output/sessions /app/output/reports /app/output/knowledge /app/output/evidence && \
    chown -R boqa:boqa /app

# Switch to non-root user
USER boqa

# Expose HTTP port
EXPOSE 7070

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "const http = require('http'); const req = http.get('http://localhost:7070/api/health', (res) => { process.exit(res.statusCode === 200 || res.statusCode === 503 ? 0 : 1); }); req.on('error', () => process.exit(1));"

# Start BOQA in live mode
CMD ["node", "server.js", "--mode=live"]

