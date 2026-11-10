FROM python:3.12-slim

# git is needed for `clone_repo` (scanning a program asset given as a git URL)
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY bountyscan ./bountyscan
RUN pip install --no-cache-dir -e .

# Persisted outside the image (see docker-compose volume): state db, cache, reports
VOLUME ["/data"]
ENV BOUNTYSCAN_DATA=/data
EXPOSE 8080

# Bind to all interfaces INSIDE the container; nginx terminates outside.
CMD ["sh", "-c", "bountyscan serve --host 0.0.0.0 --port 8080 \
     --out /data/reports --cache /data/cache --state /data/state.db"]
