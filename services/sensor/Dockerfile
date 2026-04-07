FROM rust:1.78-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/sensor /usr/local/bin/sensor
EXPOSE 8080
CMD ["/usr/local/bin/sensor"]
