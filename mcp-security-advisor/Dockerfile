FROM python:3.12-slim

WORKDIR /app

# Security: run as non-root
RUN addgroup --system mcp && adduser --system --ingroup mcp mcp

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY src/ ./src/

# Non-root user
RUN chown -R mcp:mcp /app
USER mcp

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://localhost:8080/health').raise_for_status()"

CMD ["python", "-m", "src.server"]
