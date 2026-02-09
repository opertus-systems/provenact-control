FROM rust:1.88-bookworm AS builder
WORKDIR /work

COPY . .
RUN cargo build --release -p provenact-control --features web --bin provenact-control-api

FROM debian:bookworm-slim
RUN useradd --create-home --shell /usr/sbin/nologin appuser
WORKDIR /app

COPY --from=builder /work/target/release/provenact-control-api /usr/local/bin/provenact-control-api

ENV PROVENACT_CONTROL_BIND=0.0.0.0:8080
EXPOSE 8080
USER appuser

CMD ["provenact-control-api"]
