#!/bin/sh

PORT=$1
socat \
-T300 \
TCP-LISTEN:$PORT,reuseaddr,fork \
EXEC:"timeout 300 python /ctf/sandbox.py"
