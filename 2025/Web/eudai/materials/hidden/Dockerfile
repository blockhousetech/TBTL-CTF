FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /ctf
RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt /ctf/
RUN pip install --no-cache-dir -r requirements.txt
COPY issuer_private.pem /ctf/issuer_private.pem
COPY issuer_public.pem  /ctf/issuer_public.pem
COPY app /ctf/app
COPY run.sh /ctf/run.sh
RUN chmod +x /ctf/run.sh
EXPOSE 8000
CMD ["/ctf/run.sh"]
