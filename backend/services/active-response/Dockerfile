FROM python:3.12-slim
WORKDIR /app/backend/services/active-response
COPY . /app
RUN pip install --no-cache-dir \
    fastapi==0.111.0 \
    uvicorn[standard]==0.30.1 \
    aiokafka==0.11.0 \
    aiohttp==3.9.5 \
    structlog==24.2.0 \
    pydantic==2.7.1 \
    pydantic-settings==2.3.4 \
    prometheus-fastapi-instrumentator==6.1.0
ENV PYTHONPATH=/app
USER nobody
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
