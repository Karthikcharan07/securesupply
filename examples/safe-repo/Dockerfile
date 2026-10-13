FROM python:3.12-slim
WORKDIR /app
COPY app.py .
USER 10001:10001
CMD ["python", "-c", "print('safe fixture')"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD python -c "print('healthy')"
