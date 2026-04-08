FROM rust:1.90-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p alert-engine

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/alert-engine /usr/local/bin/alert-engine
EXPOSE 8080
CMD ["/usr/local/bin/alert-engine"]
