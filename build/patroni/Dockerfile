# Patroni + PostgreSQL 18 for the watchtower nodes (linux/arm64). Patroni runs
# Postgres in this container and keeps one primary and two streaming replicas
# across the three nodes, with etcd as its consensus store (ansible/roles/patroni).
#
# Built natively on the arm64 runner (`runs-on: docker-arm64`) by
# scripts/build-image.sh, which also scans it with Trivy; never cross-built.
#
# Python and the packages come from uv: a uv-managed CPython (uv checks its
# hash) and requirements.txt, locked with hashes for arm64. Bump Patroni or
# psycopg in requirements.in and recompile (the command is in its header).
#
# Any change here needs a new tag: a new version label, or else the next
# watchtower.image.revision (back to 1 with a new version).

FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

FROM docker.io/library/postgres:18.6@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6
LABEL org.opencontainers.image.version="4.1.5"
LABEL watchtower.image.revision="1"

ENV UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PYTHON_PREFERENCE=only-managed \
    UV_NO_CACHE=1

COPY --from=uv /uv /usr/local/bin/uv
COPY requirements.txt /tmp/requirements.txt

# uv leaves the image once Python and the packages are in. So do the
# interpreter's own pip, whose vendored libraries (urllib3, msgpack,
# pkg_resources) Trivy flags and nothing here runs, and the base image's
# gosu: Patroni starts as postgres directly, never through the entrypoint.
RUN uv venv --python 3.13 /opt/patroni \
 && uv pip install --python /opt/patroni/bin/python --require-hashes --no-deps -r /tmp/requirements.txt \
 && rm -f /usr/local/bin/uv /tmp/requirements.txt /usr/local/bin/gosu \
 && rm -rf /opt/python/cpython-*/lib/python3.*/site-packages/pip \
           /opt/python/cpython-*/lib/python3.*/site-packages/pip-*.dist-info \
           /opt/python/cpython-*/lib/python3.*/ensurepip \
           /opt/python/cpython-*/bin/pip* \
 && /opt/patroni/bin/patroni --version \
 && /opt/patroni/bin/python -c 'import psycopg, etcd'

ENV PATH=/opt/patroni/bin:$PATH

# The image's postgres user (UID 999) owns the data directory.
USER postgres
ENTRYPOINT ["/opt/patroni/bin/patroni"]
CMD ["/etc/patroni/patroni.yml"]
