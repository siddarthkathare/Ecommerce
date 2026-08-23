FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vulnerable_app.py .

CMD ["python", "vulnerable_app.py"]