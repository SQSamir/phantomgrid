from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    kafka_brokers: str = "kafka:9092"
    bind_host: str = "0.0.0.0"
    decoy_manager_url: str = "http://decoy-manager:8080"
