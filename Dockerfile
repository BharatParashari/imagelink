FROM node:18-alpine

WORKDIR /app
ENV NODE_ENV=production

# Reproducible install from the committed lockfile, production deps only.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./

# Create the upload mount point owned by the non-root "node" user BEFORE the
# named volume mounts, so the volume inherits node ownership on first init.
RUN mkdir -p /uploads && chown -R node:node /uploads /app

# Drop root: the process runs as an unprivileged user.
USER node

EXPOSE 3001

# Container healthcheck (busybox wget ships with the alpine image).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3001/api/health || exit 1

CMD ["node", "server.js"]
