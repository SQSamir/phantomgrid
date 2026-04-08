FROM rust:1.90-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p tenant-manager

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/tenant-manager /usr/local/bin/tenant-manager
EXPOSE 8088
CMD ["/usr/local/bin/tenant-manager"]
