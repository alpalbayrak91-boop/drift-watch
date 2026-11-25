# SPDX-FileCopyrightText: 2026 AlpLab Research
# SPDX-License-Identifier: MIT
# Drift-Watch v3.9.1 Scale-to-Zero Edge Mirror Container (Cloud Run us-central1 Always-Free Tier)
# Zero ASCII-36 symbols; Cloud Run injects PORT and K_SERVICE automatically.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BIND_HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

RUN addgroup --system driftwatch && adduser --system --ingroup driftwatch driftwatch
COPY wrangler.toml /app/wrangler.toml
COPY src/cf_drift_watch_v39_worker.js /app/src/cf_drift_watch_v39_worker.js
COPY migrations/0001_drift_watch_v39_d1.sql /app/migrations/0001_drift_watch_v39_d1.sql
COPY server/drift_watch_edge_mirror.py /app/server/drift_watch_edge_mirror.py
RUN chown -R driftwatch:driftwatch /app

USER driftwatch
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python3", "-c", "import http.client, os, sys; c = http.client.HTTPConnection('localhost', int(os.environ.get('PORT', '8080')), timeout=2); c.request('GET', '/health'); r = c.getresponse(); sys.exit(0 if r.status == 200 else 1)"]

ENTRYPOINT ["python3", "/app/server/drift_watch_edge_mirror.py", "--serve"]
