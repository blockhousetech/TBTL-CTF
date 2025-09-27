FROM rust:1.85 AS wasm

RUN cargo install wasm-pack

# Set working directory
WORKDIR /wasm

COPY Cargo.toml Cargo.toml
COPY out.bin out.bin
COPY src/ src/

RUN wasm-pack build --release --target web

FROM python:3.10-slim

# Set working directory
WORKDIR /app

COPY --from=wasm /wasm/pkg/ /app/static/

# Install dependencies
COPY requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py /app
COPY templates/ /app/templates/

# Expose port
EXPOSE 5000

# Run both Flask and bot together
ENTRYPOINT ["waitress-serve", "--host=0.0.0.0", "--port=5000", "app:app"]
