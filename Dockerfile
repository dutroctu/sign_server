FROM python:3.9-slim-buster

WORKDIR /app
COPY requirements.txt /app/

RUN apt-get update
RUN apt-get install -y build-essential
RUN apt-get install -y iproute2

RUN pip install -r requirements.txt

# Copy app files
COPY . /app

RUN pyinstaller --onefile --add-data "templates/*:templates" --add-data "static/*:static" serverapp.py

RUN ls -l dist
RUN ls -l /tmp
# CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "app:app"]
# CMD ["gunicorn", "--bind", "0.0.0.0:6000", "--workers", "4", "serverapp:serverapp"]
CMD ["./dist/serverapp"]
# CMD ["gunicorn", "-b", "0.0.0.0:6000", "server.app:main"]