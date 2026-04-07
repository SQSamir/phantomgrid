FROM rust:1.90-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p event-processor

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/event-processor /usr/local/bin/event-processor
CMD ["/usr/local/bin/event-processor"]
