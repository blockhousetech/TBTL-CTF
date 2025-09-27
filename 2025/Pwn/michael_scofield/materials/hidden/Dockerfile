FROM python:3.12-slim

RUN apt-get update && apt-get install --yes socat

WORKDIR /ctf

COPY sandbox.py sandbox.py
COPY flag.txt flag.txt
COPY serve.sh serve.sh

RUN chmod u+x serve.sh

RUN useradd ctf
USER ctf

EXPOSE 3000
CMD [ "./serve.sh", "3000" ]
