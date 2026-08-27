FROM python:3.12-slim AS builder

WORKDIR /build
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        g++ \
        libboost-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend_server.cpp Encryption.h Decryption.h rsa_keys.h /workspace/

RUN mkdir -p /app && g++ -std=c++17 -O2 -I/workspace -o /app/backend /workspace/backend_server.cpp

FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /app/backend /app/backend
COPY webui/app.py .
COPY webui/templates templates
COPY webui/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000
CMD ["python", "app.py"]