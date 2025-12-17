FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY vt_scanner.py .

# Run the scanner
CMD ["python", "-u", "vt_scanner.py"]
