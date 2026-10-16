# Multi-stage Dockerfile for qBittorrent with Native OIDC Support
# Builds qbittorrent-nox on Alpine and packages into LinuxServer qbittorrent image

FROM alpine:3.24 AS builder

RUN apk add --no-cache \
    boost-dev \
    cmake \
    g++ \
    libtorrent-rasterbar-dev \
    openssl-dev \
    qt6-qtbase-dev \
    qt6-qtbase-private-dev \
    qt6-qtsvg-dev \
    qt6-qttools-dev \
    samurai

WORKDIR /src
COPY . .

RUN cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DGUI=OFF \
    -DWEBUI=ON \
    -DSTACKTRACE=OFF \
    -DTESTING=OFF

RUN cmake --build build --target qbittorrent-nox

# Runtime image compatible with linuxserver/qbittorrent
FROM lscr.io/linuxserver/qbittorrent:latest

RUN apk add --no-cache \
    libtorrent-rasterbar \
    qt6-qtbase \
    qt6-qtbase-sqlite \
    qt6-qtsvg

# Overwrite qbittorrent-nox with OIDC-enabled binary in both standard locations
COPY --from=builder /src/build/qbittorrent-nox /usr/bin/qbittorrent-nox
COPY --from=builder /src/build/qbittorrent-nox /app/qbittorrent-nox

RUN chmod 755 /usr/bin/qbittorrent-nox /app/qbittorrent-nox
