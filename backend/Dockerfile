FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS oqs-builder
RUN printf '%s\n' \
    'Types: deb' \
    'URIs: https://snapshot.debian.org/archive/debian/20260901T000000Z/' \
    'Suites: bookworm bookworm-updates' \
    'Components: main' \
    'Check-Valid-Until: no' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    '' \
    'Types: deb' \
    'URIs: https://snapshot.debian.org/archive/debian-security/20260901T000000Z/' \
    'Suites: bookworm-security' \
    'Components: main' \
    'Check-Valid-Until: no' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    > /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends --allow-downgrades \
       git cmake ninja-build build-essential \
       libssl3=3.0.20-1~deb12u2 \
       libssl-dev=3.0.20-1~deb12u2 \
    && rm -rf /var/lib/apt/lists/*

RUN git init /src/liboqs \
    && git -C /src/liboqs remote add origin https://github.com/open-quantum-safe/liboqs.git \
    && git -C /src/liboqs fetch --depth 1 origin 5a1a854b0dc9f2141bdc771c555ee60c37950183 \
    && git -C /src/liboqs checkout --detach FETCH_HEAD \
    && cmake -S /src/liboqs -B /src/liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_DIST_BUILD=ON \
    && cmake --build /src/liboqs/build --parallel 2 \
    && cmake --install /src/liboqs/build

FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS runtime-base
COPY --from=oqs-builder /usr/local /usr/local
RUN ldconfig \
    && useradd --create-home appuser \
    && mkdir -p /var/lib/pqc-keys /app \
    && chown -R appuser:appuser /var/lib/pqc-keys /app
ENV LD_LIBRARY_PATH=/usr/local/lib
WORKDIR /app

FROM runtime-base AS test
ENV PYTHONPATH=/app
COPY requirements-dev.lock ./requirements-dev.lock
RUN pip install --no-cache-dir --require-hashes -r requirements-dev.lock
COPY --chown=appuser:appuser app ./app
COPY --chown=appuser:appuser migrations ./migrations
COPY --chown=appuser:appuser alembic.ini ./alembic.ini
COPY --chown=appuser:appuser tests ./tests
USER appuser
CMD ["pytest", "-q"]

FROM runtime-base AS production-dependencies
COPY requirements.lock ./requirements.lock
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY --chown=appuser:appuser migrations ./migrations
COPY --chown=appuser:appuser alembic.ini ./alembic.ini

FROM production-dependencies AS runtime
COPY --chown=appuser:appuser app ./app
USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM production-dependencies AS issuer-tools
COPY --chown=appuser:appuser app ./app
USER appuser
ENTRYPOINT ["python", "-m", "app.issuer_tool"]
