# SPDX-FileCopyrightText: 2026 Alp Albayrak
# SPDX-License-Identifier: MIT
# Drift-Watch v4.0.0 Scale-to-Zero Edge Mirror Container
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BIND_HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

RUN addgroup --system driftwatch && adduser --system --ingroup driftwatch driftwatch
COPY pyproject.toml README.md wrangler.toml /app/
COPY src /app/src
COPY worker /app/worker
COPY migrations /app/migrations
COPY server /app/server
RUN pip install --no-cache-dir -e . && chown -R driftwatch:driftwatch /app

USER driftwatch
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python3", "-c", "import http.client, os, sys; c = http.client.HTTPConnection('localhost', int(os.environ.get('PORT', '8080')), timeout=2); c.request('GET', '/health'); r = c.getresponse(); sys.exit(0 if r.status == 200 else 1)"]

ENTRYPOINT ["python3", "/app/server/drift_watch_edge_mirror.py", "--serve"]
