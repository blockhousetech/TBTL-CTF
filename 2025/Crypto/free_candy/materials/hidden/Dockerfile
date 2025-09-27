FROM sagemath/sagemath:latest

ENV SAGE_NUM_THREADS=1 \
    PYTHONUNBUFFERED=1 \
    PORT=1337 \
    TIMEOUT=120

USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends socat && \
    rm -rf /var/lib/apt/lists/*

# Install pycryptodome into Sage's Python (for Crypto.Util.number)
RUN sage -python -m ensurepip --upgrade || true && \
    sage -python -m pip install --no-cache-dir pycryptodome

RUN mkdir -p /home/sage/chal
COPY server.py /home/sage/chal/server.py
COPY flag.txt   /home/sage/chal/flag.txt
RUN chown -R sage:sage /home/sage

USER sage
WORKDIR /home/sage/chal
EXPOSE 1337

ENTRYPOINT ["/bin/sh","-c","exec socat -T ${TIMEOUT:-120} TCP-LISTEN:${PORT:-1337},bind=0.0.0.0,reuseaddr,fork EXEC:\"sage -python server.py\""]
