FROM python:3.11-slim

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends socat && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pycryptodome

RUN useradd -m ctf
WORKDIR /home/ctf/challenge

COPY server.py .
COPY flag.txt .

RUN chmod 440 flag.txt          && \
    chown root:ctf flag.txt     && \
    chmod 555 server.py

USER ctf
ENV PYTHONUNBUFFERED=1
EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork \
          EXEC:"python3 /home/ctf/challenge/server.py",stderr,setsid
