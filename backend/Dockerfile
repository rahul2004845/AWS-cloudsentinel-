FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home appuser && mkdir -p /var/lib/cloudsentinel && chown -R appuser:appuser /app /var/lib/cloudsentinel
USER appuser
ENV SQLITE_DB_PATH=/var/lib/cloudsentinel/cloudsentinel.db
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
