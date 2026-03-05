# Docker Compose Quickstart

## 1) Prepare environment

```bash
cd deploy/docker-compose
cp .env.example .env
```

Edit `.env` and set production-safe secrets.

## 2) Start stack

```bash
docker compose up --build
```

ReleaseGate API will be available at `http://localhost:8000`.

## 3) Verify

```bash
curl -s http://localhost:8000/health | jq
```

## 4) Stop

```bash
docker compose down
```
