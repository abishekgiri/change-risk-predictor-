FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN addgroup --system releasegate && adduser --system --ingroup releasegate releasegate

WORKDIR /app

COPY requirements.txt pyproject.toml /app/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . /app
RUN pip install --no-cache-dir -e .

RUN mkdir -p /app/data && chown -R releasegate:releasegate /app
USER releasegate

EXPOSE 8000

CMD ["uvicorn", "releasegate.server:app", "--host", "0.0.0.0", "--port", "8000", "--log-config", "/app/deploy/docker/uvicorn_log_config.json"]
