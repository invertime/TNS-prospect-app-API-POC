FROM python:3.14

WORKDIR /app

ADD ./src /app/
ADD requirements.txt /app

RUN apt update \
    pip install -r requirements.txt


ENV ENV_FILE_LOCATION=../.env

EXPOSE 8000

CMD [ "python", "src/__init__.py" ]
