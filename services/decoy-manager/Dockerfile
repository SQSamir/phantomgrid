FROM rust:1.90-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p decoy-manager

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/decoy-manager /usr/local/bin/decoy-manager
EXPOSE 8082
CMD ["/usr/local/bin/decoy-manager"]
