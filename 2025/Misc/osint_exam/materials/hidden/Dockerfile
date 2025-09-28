FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y socat \
    && rm -rf /var/lib/apt/lists/*

COPY server.py /usr/local/bin/server.py
RUN chmod +x /usr/local/bin/server.py

EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/usr/local/bin/server.py"]
