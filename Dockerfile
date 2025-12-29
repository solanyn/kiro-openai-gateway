FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/deps -r requirements.txt

FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /deps /deps
COPY kiro_gateway kiro_gateway
COPY main.py .

ENV PYTHONPATH=/deps
EXPOSE 8000

CMD ["python", "main.py"]
