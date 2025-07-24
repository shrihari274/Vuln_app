# Dockerfile
FROM python:3.8-slim

WORKDIR /app

COPY . /app

# Install specific versions known to work with older Flask apps
RUN pip install flask==1.1.2 \
    jinja2==2.11.3 \
    markupsafe==2.0.1 \
    itsdangerous==1.1.0 \
    werkzeug==1.0.1

EXPOSE 5000

CMD ["python", "app.py"]

