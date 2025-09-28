FROM python:3.12-slim

# Install dependencies
RUN apt-get update && apt-get install -y socat python3-pip \
    && pip install pytest

# Set working directory
WORKDIR /app

# Copy challenge files
COPY docs4bucks.py flag_checker.py ./
COPY resources ./resources

# Make the main script executable
RUN chmod +x docs4bucks.py

# Expose the CTF port
EXPOSE 2000

# Launch via socat to serve over TCP
CMD ["socat", "TCP-LISTEN:2000,reuseaddr,fork", "EXEC:python3 docs4bucks.py"]
