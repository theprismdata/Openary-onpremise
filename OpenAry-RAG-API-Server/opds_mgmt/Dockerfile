FROM python:3.10.10-slim

RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip install psycopg2

WORKDIR /app
RUN mkdir -p /app/log
RUN mkdir -p /config
COPY ./requirements.txt /app/requirements.txt
COPY ./opds_mgmt_user.py /app/opds_mgmt_user.py

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "opds_mgmt_user.py"]