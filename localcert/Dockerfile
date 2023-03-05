FROM python:3

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY . /app/

ENTRYPOINT [ "gunicorn", "--workers=3", "--bind=0.0.0.0:80", "--env", "DJANGO_SETTINGS_MODULE=localcert.settings", "localcert.wsgi"]
