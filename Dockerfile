FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt pyproject.toml ./
COPY securesupply ./securesupply
RUN pip install --no-cache-dir --upgrade pip setuptools && pip install --no-cache-dir .
USER 10001:10001
ENTRYPOINT ["python", "-m", "securesupply"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD python -c "import securesupply" || exit 1
