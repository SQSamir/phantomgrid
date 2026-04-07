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
