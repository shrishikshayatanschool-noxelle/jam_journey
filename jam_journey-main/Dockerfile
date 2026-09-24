FROM node:22-alpine
WORKDIR /app
COPY index.html styles.css app.js server.mjs README.md ./
ENV NODE_ENV=production HOST=0.0.0.0
EXPOSE 4173
CMD ["node", "server.mjs"]

