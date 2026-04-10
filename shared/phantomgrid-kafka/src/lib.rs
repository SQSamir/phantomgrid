#![deny(warnings)]

use anyhow::Context;
use rdkafka::{
    config::ClientConfig,
    consumer::{Consumer, StreamConsumer},
    producer::{FutureProducer, FutureRecord},
    Message,
};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

pub async fn create_producer(brokers: &str) -> FutureProducer {
    loop {
        match ClientConfig::new().set("bootstrap.servers", brokers).create() {
            Ok(p) => break p,
            Err(e) => {
                tracing::error!(error = %e, "failed to create kafka producer, retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

pub async fn send_event<T: Serialize>(producer: &FutureProducer, topic: &str, key: &str, payload: &T) {
    let body = match serde_json::to_string(payload) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, topic, "failed to serialize kafka payload");
            return;
        }
    };

    if let Err((e, _)) = producer
        .send(
            FutureRecord::to(topic).key(key).payload(&body),
            Duration::from_secs(5),
        )
        .await
    {
        tracing::error!(error = %e, topic, "failed to send kafka message");
    }
}

pub fn create_consumer(brokers: &str, group_id: &str) -> StreamConsumer {
    loop {
        let consumer: Result<StreamConsumer, _> = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("group.id", group_id)
            .set("enable.partition.eof", "false")
            .set("auto.offset.reset", "earliest")
            .create();

        match consumer {
            Ok(c) => break c,
            Err(e) => {
                tracing::error!(error = %e, "failed to create kafka consumer, retrying");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

pub fn subscribe(consumer: &StreamConsumer, topics: &[&str]) {
    if let Err(e) = consumer.subscribe(topics) {
        tracing::error!(error = %e, ?topics, "failed to subscribe kafka topics");
    }
}

pub fn producer(brokers: &str) -> anyhow::Result<FutureProducer> {
    ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .create()
        .with_context(|| "failed to create kafka producer")
}

pub fn consumer(group_id: &str, brokers: &str, topics: &[&str]) -> anyhow::Result<StreamConsumer> {
    let c: StreamConsumer = ClientConfig::new()
        .set("group.id", group_id)
        .set("bootstrap.servers", brokers)
        .set("enable.partition.eof", "false")
        .set("auto.offset.reset", "earliest")
        .create()
        .with_context(|| "failed to create kafka consumer")?;
    c.subscribe(topics).with_context(|| "failed to subscribe topics")?;
    Ok(c)
}

pub async fn publish_json<T: Serialize>(producer: &FutureProducer, topic: &str, key: &str, value: &T) -> anyhow::Result<()> {
    let payload = serde_json::to_string(value)?;
    producer
        .send(FutureRecord::to(topic).key(key).payload(&payload), Duration::from_secs(5))
        .await
        .map_err(|(e, _)| anyhow::anyhow!(e))?;
    Ok(())
}

pub fn parse_json<T: DeserializeOwned>(msg: &impl Message) -> anyhow::Result<T> {
    let bytes = msg.payload().ok_or_else(|| anyhow::anyhow!("empty payload"))?;
    Ok(serde_json::from_slice(bytes)?)
}
