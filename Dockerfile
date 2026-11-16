# Builds for the platform it is built on: arm64 on an Apple-silicon host,
# amd64 on Intel. No emulation, no C compiler (SQLite is pure Go here).
FROM node:24-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /openmdm ./cmd/openmdm

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 openmdm && mkdir /data && chown openmdm /data
USER openmdm
COPY --from=build /openmdm /usr/local/bin/openmdm
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["openmdm"]
CMD ["--config", "/etc/openmdm/openmdm.yaml"]
