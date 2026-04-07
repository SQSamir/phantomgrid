#![deny(warnings)]
use anyhow::Context;
use sqlx::{migrate::Migrator, PgPool};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPool::connect(database_url)
        .await
        .with_context(|| "failed to connect postgres")?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    MIGRATOR.run(pool).await.with_context(|| "migration failed")?;
    Ok(())
}
