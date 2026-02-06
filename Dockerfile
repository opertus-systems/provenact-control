FROM rust:1.86-bookworm AS builder
WORKDIR /work

COPY . .
RUN cargo build --release -p inactu-control --features web --bin inactu-control-web

FROM debian:bookworm-slim
RUN useradd --create-home --shell /usr/sbin/nologin appuser
WORKDIR /app

COPY --from=builder /work/target/release/inactu-control-web /usr/local/bin/inactu-control-web

ENV INACTU_CONTROL_BIND=0.0.0.0:8080
EXPOSE 8080
USER appuser

CMD ["inactu-control-web"]
