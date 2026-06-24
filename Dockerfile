FROM python:3.14 AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.14-slim
ENV PYTHONUNBUFFERED=1 PATH=/root/.local/bin:$PATH
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY sync.py .
ENTRYPOINT ["python", "/app/sync.py"]
