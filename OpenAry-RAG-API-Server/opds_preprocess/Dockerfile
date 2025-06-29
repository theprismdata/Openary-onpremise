FROM python:3.10.10-slim

ENV ENVIRONMENT=production

WORKDIR /app
RUN mkdir /test
RUN mkdir -p /app/log
RUN mkdir -p /config
COPY ./HwpParser.py /app/HwpParser.py
COPY ./Preprocess_Subscriber.py /app/Preprocess_Subscriber.py
COPY ./requirements.txt /app/requirements.txt

ENV ENVIRONMENT=production

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "Preprocess_Subscriber.py"]