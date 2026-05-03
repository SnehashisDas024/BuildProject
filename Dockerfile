FROM python:3.11

WORKDIR /app

# Copy the backend code and requirements
COPY backend /app/backend

# Install dependencies
RUN pip install --no-cache-dir -r backend/requirements.txt

# Expose the port
EXPOSE 8080

# Run the FastAPI application
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
