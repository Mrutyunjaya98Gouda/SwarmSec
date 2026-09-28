FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/src/
ENV PYTHONPATH=/app/src

# Default to registrar, but can be overridden
CMD ["uvicorn", "swarmsec.registrar.app:app", "--host", "0.0.0.0", "--port", "8000"]
