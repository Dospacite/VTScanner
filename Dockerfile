FROM ghcr.io/d4vinci/scrapling:latest

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vt_scanner.py .

ENTRYPOINT ["python", "-u", "vt_scanner.py"]
