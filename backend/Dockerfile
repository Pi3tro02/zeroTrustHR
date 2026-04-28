FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --include=dev

COPY . .

RUN npx tsc

EXPOSE 3000

CMD ["node", "dist/server.js"]