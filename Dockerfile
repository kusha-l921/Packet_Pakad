FROM alpine:3.19 AS builder

RUN apk add --no-cache \
    build-base \
    cmake \
    ninja \
    git \
    openssl-dev \
    linux-headers \
    bison \
    flex \
    gperf \
    gmp-dev \
    autoconf \
    automake \
    libtool \
    gettext-dev \
    pkgconf \
    python3


WORKDIR /src

# strongSwan 6.0.x has NATIVE post-quantum ML-KEM (FIPS 203) support via the
# bundled "ml" plugin — no liboqs, no external PQC library required.
RUN git clone --depth 1 --branch 6.0.2 https://github.com/strongswan/strongswan.git && \
    cd strongswan && \
    ./autogen.sh && \
    ./configure --prefix=/usr --sysconfdir=/etc \
        --enable-swanctl \
        --enable-vici \
        --enable-openssl \
        --enable-ml \
        --enable-gcm \
        --enable-silent-rules \
        --disable-gmp && \
    make -j$(nproc) && \
    make install

# --- Final Production Stage ---
FROM alpine:3.19

RUN apk add --no-cache \
    openssl \
    iproute2 \
    iptables \
    tcpdump \
    bash \
    python3 \
    gmp

# strongSwan runtime binaries and plugins
COPY --from=builder /usr/lib/ipsec /usr/lib/ipsec
COPY --from=builder /usr/libexec/ipsec /usr/libexec/ipsec
COPY --from=builder /usr/sbin/swanctl /usr/sbin/swanctl

# Config: strongswan.conf + strongswan.d (per-plugin load config, incl. ml.conf)
# and swanctl.conf — omitting these means the ml plugin never gets loaded
# at runtime even though it built fine.
COPY --from=builder /etc/strongswan.conf /etc/strongswan.conf
COPY --from=builder /etc/strongswan.d /etc/strongswan.d
COPY --from=builder /etc/swanctl /etc/swanctl

RUN mkdir -p /etc/swanctl/x509 /etc/swanctl/pkcs8 /captures

CMD ["/usr/libexec/ipsec/charon"]