# Use a slim Python image for smaller size
FROM python:3.14-slim

# Set working directory
WORKDIR /app

# Copy application code and static assets
COPY app.py .
COPY static/ ./static/

# Install dependencies during build, not runtime
# Added 'PyYAML' to fix the ModuleNotFoundError
RUN pip install --no-cache-dir flask requests urllib3 PyYAML

# Expose the port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
