FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 app
WORKDIR /app

COPY requirements.txt .
# Base image bawa pip/setuptools lama yang kena advisory (pip-audit).
RUN pip install --no-cache-dir --upgrade pip==26.2.2 setuptools==84.2.1 \
 && pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app . .
RUN chmod +x /app/docker-entrypoint.sh
USER app

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--access-logfile", "-", "app:app"]
