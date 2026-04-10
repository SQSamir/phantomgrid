FROM python:3.12-slim
WORKDIR /app/backend/services/analytics
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
ENV PYTHONPATH=/app
USER nobody
CMD ["python", "main.py"]
