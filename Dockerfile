FROM python:3.14

WORKDIR /app

ADD ./src /app/
ADD requirements.txt /app
ADD .env /app

RUN apt update
RUN pip install -r requirements.txt

ENV ENV_FILE_LOCATION=.env

EXPOSE 8000

CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w","4", "__init__:app", "--preload"]
