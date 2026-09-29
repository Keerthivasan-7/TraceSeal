# syntax=docker/dockerfile:1.7

FROM node:22.20.0-alpine3.22 AS build
WORKDIR /app
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM nginx:1.29.1-alpine3.22 AS runtime
RUN apk add --no-cache iproute2
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --chmod=755 web/docker-entrypoint.sh /usr/local/bin/traceseal-web-entrypoint
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/traceseal-web-entrypoint"]
