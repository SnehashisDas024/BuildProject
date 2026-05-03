FROM python:3.11

WORKDIR /app

# Copy the backend and frontend code
COPY backend /app/backend
COPY frontend /app/frontend

# Install dependencies
RUN pip install --no-cache-dir -r backend/requirements.txt

# Start the FastAPI application on the port provided by Cloud Run
WORKDIR /app/backend
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
