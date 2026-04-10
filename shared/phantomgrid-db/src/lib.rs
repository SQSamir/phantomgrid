#![deny(warnings)]

use anyhow::Context;
use sqlx::{migrate::Migrator, postgres::{PgPool, PgPoolOptions}};
use std::time::Duration;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(20)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await
}

pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    create_pool(database_url)
        .await
        .with_context(|| "failed to connect postgres")
}

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    MIGRATOR.run(pool).await.with_context(|| "migration failed")?;
    Ok(())
}
