FROM node:20-bookworm-slim AS build

WORKDIR /app

COPY package.json ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:20-bookworm-slim

WORKDIR /app

ENV NODE_ENV=production

COPY --from=build /app/dist ./dist

EXPOSE 8080

ENTRYPOINT ["node", "dist/index.js"]