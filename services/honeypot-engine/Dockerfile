FROM rust:1.90-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p honeypot-engine

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/honeypot-engine /usr/local/bin/honeypot-engine
EXPOSE 18080 10022 10023 16379
CMD ["/usr/local/bin/honeypot-engine"]
