FROM python:3.10-slim

RUN apt-get update && \
    apt-get install -y \
    firefox-esr \
    curl \
    ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py /app
COPY admin.py /app
COPY static/ /app/static/
COPY templates/ /app/templates/

ENV ADMIN_SECRET=8cff4084-6ec1-4247-ae37-c03bd9058d3a
ENV FLAG=FortID{50m371m35_15_b3773r_70_n07_v1b3_c0d3_4nd_0buf5c473}

# Expose port
EXPOSE 5000

# Run both Flask and bot together
ENTRYPOINT ["waitress-serve", "--host=0.0.0.0", "--port=5000", "--threads=16", "--connection-limit=400","app:app"]
