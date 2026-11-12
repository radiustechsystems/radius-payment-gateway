# syntax=docker/dockerfile:1.7
#
# radius-gateway as a container. Everything it needs is in this repository (the policy
# evaluator is vendored), so a plain build works anywhere:
#
#   docker build --build-arg RADIUS_GATEWAY_COMMIT=$(git rev-parse --short=9 HEAD) \
#     -t radius-gateway .
#
# The result is a distroless image (no shell) running as a non-root user, about the size of the
# binary. Configure it with the environment variables the README lists.

ARG RUST_VERSION=1.97.0

# ---------------------------------------------------------------- build
FROM rust:${RUST_VERSION}-slim-bookworm AS builder

# cmake builds the TLS library's C code (aws-lc).
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# The git commit this image is built from; see build.rs. Pass it in, since .git isn't copied.
ARG RADIUS_GATEWAY_COMMIT=unknown
ENV RADIUS_GATEWAY_COMMIT=${RADIUS_GATEWAY_COMMIT}

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && cp target/release/radius-gateway /radius-gateway

# ---------------------------------------------------------------- run
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /radius-gateway /usr/local/bin/radius-gateway

# Inside a container the admin listener has to bind beyond loopback to be reachable; keep its
# port off the public network.
ENV LISTEN=0.0.0.0:8080 \
    ADMIN_LISTEN=0.0.0.0:9901

EXPOSE 8080 9901
USER nonroot
ENTRYPOINT ["/usr/local/bin/radius-gateway"]
