ARG NODE_IMAGE=node:20.19.4-alpine3.21
FROM ${NODE_IMAGE}

WORKDIR /opt/p21
COPY server.js isolation-probe.js ./

USER node
EXPOSE 8080
CMD ["node", "server.js"]
