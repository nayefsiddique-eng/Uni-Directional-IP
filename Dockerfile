FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for network capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Environment variable for unbuffered logging
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "src/main.py"]
