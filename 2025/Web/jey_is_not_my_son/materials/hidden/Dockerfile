FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py /app
COPY templates/ /app/templates/
COPY data.json /app

# Expose port
EXPOSE 5000

# Run both Flask and bot together
ENTRYPOINT ["waitress-serve", "--host=0.0.0.0", "--port=5000", "app:app"]
