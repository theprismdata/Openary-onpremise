FROM python:3.10.10-slim

ENV ENVIRONMENT=production

RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip install psycopg2

WORKDIR /app
RUN mkdir -p /app/log
RUN mkdir -p /config
COPY ./requirements.txt /app/requirements.txt
COPY ./check_token.py /app/check_token.py
COPY ./Summary_Subscriber.py /app/Summary_Subscriber.py

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "Summary_Subscriber.py"]