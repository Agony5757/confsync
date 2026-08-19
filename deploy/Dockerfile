FROM python:3.12-slim

# Deploy target is behind the GFW; default to a China PyPI mirror.
# Override with: docker compose build --build-arg PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/
ENV PIP_INDEX_URL=${PIP_INDEX_URL}

WORKDIR /app
COPY server/ /app/server/
RUN pip install --no-cache-dir /app/server

ENV CONFSYNC_HOME=/data
VOLUME /data
EXPOSE 8930

CMD ["confsync-server", "serve", "--host", "0.0.0.0", "--port", "8930"]
