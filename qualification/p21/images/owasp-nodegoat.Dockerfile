ARG NODE_IMAGE=node@sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498

FROM ${NODE_IMAGE} AS dependencies
WORKDIR /src
COPY package.json package-lock.json ./
ENV CYPRESS_INSTALL_BINARY=0
RUN npm ci --omit=dev --no-audit --fund=false

FROM ${NODE_IMAGE}
RUN addgroup -g 10001 p21 && adduser -D -u 10001 -G p21 -h /home/p21 p21
WORKDIR /home/p21/app
COPY --from=dependencies --chown=10001:10001 /src/node_modules ./node_modules
COPY --chown=10001:10001 . .
ENV NODE_ENV=test
ENV PORT=4000
USER 10001:10001
EXPOSE 4000
CMD ["node", "server.js"]
