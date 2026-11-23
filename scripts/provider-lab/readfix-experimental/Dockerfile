FROM docker.io/library/python@sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4
COPY requirements-fixture.txt /opt/requirements-fixture.txt
RUN python3 -m venv /opt/venv && /opt/venv/bin/python -m pip --isolated --disable-pip-version-check install --no-cache-dir --require-hashes --only-binary=:all: --index-url https://pypi.org/simple --retries 0 --timeout 20 -r /opt/requirements-fixture.txt
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONNOUSERSITE=1 HOME=/work TMPDIR=/work
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/opt/venv/bin/python"]
CMD ["/opt/prototype/probe.py"]
