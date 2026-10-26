FROM python:3.12-slim
COPY app.py /app/app.py
RUN mkdir -p /data && chown 65534:65534 /data
USER 65534
EXPOSE 8080 8443
CMD ["python3", "/app/app.py"]
