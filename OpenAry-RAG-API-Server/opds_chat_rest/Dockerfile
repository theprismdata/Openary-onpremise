FROM python:3.10.10-slim

ENV ENVIRONMENT=production

RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip install psycopg2
WORKDIR /app
RUN mkdir -p /app/log
RUN mkdir -p /app/embeddingmodel
RUN mkdir -p /config
COPY ./requirements.txt /app/requirements.txt
COPY ./DataModel.py /app/DataModel.py
COPY ./DBHandler.py /app/DBHandler.py
COPY ./opds_chat_api_fastapi.py /app/opds_chat_api_fastapi.py
COPY ./question_classifier.py /app/question_classifier.py
COPY ./LLMIntentAnalyzer.py /app/LLMIntentAnalyzer.py
COPY ./LLMSelector.py /app/LLMSelector.py

RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "opds_chat_api_fastapi.py"]
