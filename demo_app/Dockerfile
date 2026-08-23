FROM python:3.12-slim

# Secure baseline: run as a non-root user, no build tools left in the image.
RUN useradd --create-home appuser
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/

USER appuser
ENV STORE_SECRET_KEY=""

EXPOSE 5050
CMD ["python", "app.py"]
