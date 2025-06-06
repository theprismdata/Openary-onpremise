FROM python:3.10.10-slim

ENV ENVIRONMENT=production

RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip install psycopg2

WORKDIR /app
RUN mkdir -p /app/log
RUN mkdir -p /app/embeddingmodel
RUN mkdir -p /config
#COPY ./embeddingmodel /app/embeddingmodel
COPY ./requirements.txt /app/requirements.txt
COPY ./Embedding_Subscriber.py /app/Embedding_Subscriber.py

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "Embedding_Subscriber.py"]