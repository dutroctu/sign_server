FROM python:3.9-slim-buster

WORKDIR /app
COPY requirements.txt /app/

RUN pip install -r requirements.txt
RUN apt-get update
RUN apt-get install -y build-essential

# Copy app files
COPY . /app

RUN pyinstaller --onefile --add-data "templates/*:templates" --add-data "static/*:static" serverapp.py

# CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "app:app"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--access-logfile", "-", "--error-logfile", "-", "--capture-output", "--log-level", "debug", "--log-file", "-","app:app"]
