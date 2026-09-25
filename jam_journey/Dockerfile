FROM node:22-alpine
WORKDIR /app
COPY jam_journey-main-edited/ ./
ENV NODE_ENV=production HOST=0.0.0.0
EXPOSE 4173
CMD ["node", "server.mjs"]
