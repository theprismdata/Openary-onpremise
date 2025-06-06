import json
import os
import sys
import time
from pprint import pprint
import pymongo
import yaml
import pika
import logging
import pymysql
from logging.handlers import TimedRotatingFileHandler
import psycopg2
from langchain.text_splitter import NLTKTextSplitter
import pandas as pd
import nltk
from langchain_community.embeddings import HuggingFaceEmbeddings
import ssl
from contextlib import contextmanager
from functools import lru_cache

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

ENV = os.getenv('ENVIRONMENT', 'development')
config_file = f'../config/svc-set.{"debug." if ENV == "development" else ""}yaml'

with open(config_file) as f:
    config = yaml.load(f, Loader=yaml.FullLoader)


print("build:2025-02-26#09:30")
if not os.path.exists("log"):
    os.makedirs("log")

# 로깅 설정
logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)

f_format = logging.Formatter('[%(asctime)s][%(levelname)s|%(filename)s:%(lineno)s] --- %(message)s')

path = "log/preprocess.log"
file_handler = TimedRotatingFileHandler(path,
                                        when="h",
                                        interval=1,
                                        backupCount=24)
file_handler.namer = lambda name: name + ".txt"
file_handler.setFormatter(f_format)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(f_format)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# 설정 값 가져오기
mongo_host = config['database']['mongodb']['mongo_host']
mongo_port = config['database']['mongodb']['mongo_port']
mongo_user = config['database']['mongodb']['mongo_user']
mongo_passwd = config['database']['mongodb']['mongo_passwd']
auth_source = config['database']['mongodb']['auth_source']

vector_postgres = config['database']['vector_db_postgres']
opds_system_db = config['database']['opds_system_db']

mqtt_info = config['mqtt']
mqtt_id = mqtt_info['id']
mqtt_pwd = mqtt_info['pwd']
mqtt_address = mqtt_info['address']
mqtt_port = mqtt_info['port']
mqtt_virtualhost = mqtt_info['virtualhost']

RABBITMQ_SVC_QUEUE = config['RABBITMQ_SVC_QUEUE']

# MongoDB 연결 문자열
mongo_uri = f"mongodb://{mongo_user}:{mongo_passwd}@{mongo_host}:{mongo_port}/?authSource={auth_source}&authMechanism=SCRAM-SHA-1"

# 임베딩 모델 설정
EMBEDDING_MODEL_ID = config['embeddingmodel']['sentensetransformer']['embedding_model']

if not os.path.exists(f'./embeddingmodel/{EMBEDDING_MODEL_ID}'):
    hugging_cmd = f'huggingface-cli download {EMBEDDING_MODEL_ID} --local-dir ./embeddingmodel/{EMBEDDING_MODEL_ID}'
    os.system(hugging_cmd)

# 임베딩 모델 로드 (늦은 초기화)
_embedding_model = None


def get_embedding_model():
    global _embedding_model
    if _embedding_model is None:
        _embedding_model = HuggingFaceEmbeddings(
            model_name=f'./embeddingmodel/{EMBEDDING_MODEL_ID}/',
            model_kwargs={'device': 'cpu'}
        )
    return _embedding_model


# NLTK 다운로드 및 설정
nltk.download('punkt_tab')
chunk_size = 1000
nltk_text_spliter = NLTKTextSplitter(
    chunk_size=chunk_size,
    separator='\n',
    chunk_overlap=chunk_size)


# 연결 풀 관리를 위한 컨텍스트 매니저들
@contextmanager
def get_mongo_connection():
    """MongoDB 연결 컨텍스트 매니저"""
    client = pymongo.MongoClient(mongo_uri, maxPoolSize=10)
    try:
        yield client[auth_source]
    finally:
        client.close()


@contextmanager
def get_postgres_connection():
    """PostgreSQL 연결 컨텍스트 매니저"""
    conn = psycopg2.connect(
        host=vector_postgres['address'],
        dbname=vector_postgres['database'],
        user=vector_postgres['id'],
        password=vector_postgres['pwd'],
        port=vector_postgres['port']
    )
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def get_mysql_connection():
    """MySQL 연결 컨텍스트 매니저"""
    conn = pymysql.connect(
        user=opds_system_db["id"],
        password=opds_system_db["pwd"],
        database=opds_system_db["database"],
        host=opds_system_db["address"],
        port=opds_system_db["port"]
    )
    try:
        yield conn
    finally:
        conn.close()


@lru_cache(maxsize=100)
def get_user_code(email):
    """사용자 코드 조회 (캐시 적용)"""
    with get_mysql_connection() as conn:
        sql = f'SELECT `id`, user_code FROM tb_user WHERE email="{email}"'
        with conn.cursor() as cs:
            cs.execute(sql)
            rs = cs.fetchall()
            code_df = pd.DataFrame(rs, columns=['id', 'user_code'])

    if code_df.shape[0] == 1:
        cd = code_df.iloc[0].to_dict()
        return cd['user_code']
    return None


def sentent_embedding(sentence):
    """문장 임베딩 함수"""
    embedded_content = get_embedding_model().embed_query(sentence)
    return embedded_content


def create_connection():
    """RabbitMQ 연결 생성"""
    credentials = pika.PlainCredentials(mqtt_id, mqtt_pwd)
    param = pika.ConnectionParameters(
        host=mqtt_address,
        port=mqtt_port,
        virtual_host=mqtt_virtualhost,
        credentials=credentials,
        heartbeat=30,
        blocked_connection_timeout=30
    )
    return pika.BlockingConnection(param)


def update_embedding_progress(user_code, doc_id, progress):
    """임베딩 진행률 업데이트"""
    with get_mysql_connection() as conn:
        with conn.cursor() as cs:
            sql = f"""UPDATE {opds_system_db["database"]}.tb_llm_doc 
                     SET embedding_rate = {progress} 
                     WHERE userid='{user_code}' AND id = '{doc_id}'"""
            cs.execute(sql)
            conn.commit()


def batch_insert_vectors(user_code, vectors_data):
    """벡터 데이터 일괄 삽입"""
    if not vectors_data:
        return

    with get_postgres_connection() as conn:
        with conn.cursor() as cursor:
            # 다중 행 삽입을 위한 쿼리 구성
            args_str = ','.join(cursor.mogrify("(%s, %s, %s, %s)", x).decode('utf-8') for x in vectors_data)
            insert_query = f"INSERT INTO {user_code} (doc_id, source, text, vector) VALUES " + args_str
            cursor.execute(insert_query)
            conn.commit()


def wait_mq_signal(ch, method, properties, body):
    """메시지 큐 처리 콜백"""
    body = body.decode('utf-8')
    msg_json = json.loads(body)
    print("Embedding Subscribe")
    logger.debug(msg_json)

    try:
        user_code = msg_json['user_code']
        doc_id = msg_json['doc_id']
        file_name = msg_json['file_name']

        # MongoDB에서 데이터 조회 - find_one 사용하여 바로 단일 문서 가져오기
        with get_mongo_connection() as mongodb_genai:
            file_doc = mongodb_genai[user_code].find_one(
                {"id": doc_id, "filename": file_name, "embedding": "ready"},
                {"id": 1, "filename": 1, "cleansing": 1, "clean_doc": 1, "embedding": 1}
            )

        if not file_doc:
            logger.warning(f"doc id {doc_id} not exist")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return
        if file_doc['embedding'] != "ready" or file_doc['clean_doc'] is None:
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        clean_doc = file_doc['clean_doc']
        filename = file_doc['filename']

        # 벡터 DB에서 기존 데이터 삭제
        with get_postgres_connection() as vector_db:
            with vector_db.cursor() as cursor:
                # 기존 데이터 확인 및 삭제
                select_query = f"SELECT COUNT(*) AS ROWCOUNT FROM {user_code} WHERE doc_id = %s"
                cursor.execute(select_query, (doc_id,))
                count_row = cursor.fetchone()

                if count_row[0] > 0:
                    delete_query = f"DELETE FROM {user_code} WHERE doc_id = %s"
                    cursor.execute(delete_query, (doc_id,))
                    vector_db.commit()

        logger.debug(f"append user {user_code} file id {doc_id}")

        # 텍스트 청크로 분할
        chunk_tokens = nltk_text_spliter.split_text(clean_doc)
        len_chunk = len(chunk_tokens)

        # 벡터 삽입을 위한 배치 처리 (배치 크기: 50)
        batch_size = 50
        vectors_batch = []

        for ci, clean_text in enumerate(chunk_tokens, 1):
            try:
                # 임베딩 생성
                embedded_content = sentent_embedding(clean_text)

                # 특수 문자 처리
                clean_text = clean_text.encode().decode().replace("\x00", "")
                clean_text = clean_text.replace("'", "''")

                # 배치에 추가
                vectors_batch.append((doc_id, filename, clean_text, str(embedded_content)))

                # 배치 크기에 도달하거나 마지막 항목이면 삽입
                if len(vectors_batch) >= batch_size or ci == len_chunk:
                    batch_insert_vectors(user_code, vectors_batch)
                    vectors_batch = []

                # 진행률 업데이트 (10% 단위로만)
                progress = int((ci / len_chunk) * 100)
                if progress % 10 == 0:
                    update_embedding_progress(user_code, doc_id, progress)

            except Exception as e:
                logger.error(f"Error processing chunk {ci} for doc id {doc_id}: {str(e)}")

        # 처리 완료 후 MongoDB 상태 업데이트
        with get_mongo_connection() as mongodb_genai:
            mongodb_genai[user_code].update_one(
                {"id": doc_id, "filename": filename},
                {"$set": {"cleansing": "finish", "embedding": "finish"}}
            )

        logger.debug(f"doc id {doc_id} embedding finish")
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")
        ch.basic_ack(delivery_tag=method.delivery_tag)  # 오류 시에도 메시지 승인 (재처리 방지)


def cleanup_connection(connection):
    """연결 정리 함수"""
    try:
        if connection and not connection.is_closed:
            connection.close()
    except pika.exceptions.ConnectionWrongStateError:
        logger.warning("Connection already closed")
    except Exception as e:
        logger.error(f"Error closing connection: {str(e)}")


if __name__ == '__main__':
    while True:
        connection = None
        try:
            print("Embedding consumer start")
            logger.info("Embedding consumer start")
            connection = create_connection()

            OPDS_EMBEDDING_Channel = connection.channel()
            OPDS_EMBEDDING_REQ_Qname = RABBITMQ_SVC_QUEUE['EMBEDDING_Q_NAME']
            OPDS_EMBEDDING_Channel.queue_declare(queue=OPDS_EMBEDDING_REQ_Qname)
            OPDS_EMBEDDING_Channel.basic_qos(prefetch_count=1)  # 한 번에 하나의 메시지만 처리
            OPDS_EMBEDDING_Channel.basic_consume(
                queue=OPDS_EMBEDDING_REQ_Qname,
                on_message_callback=wait_mq_signal,
                auto_ack=False
            )

            logger.info("Embedding consumer ready")
            OPDS_EMBEDDING_Channel.start_consuming()

        except pika.exceptions.StreamLostError:
            logger.error("Connection lost. Reconnecting...")
            time.sleep(5)
            cleanup_connection(connection)

        except pika.exceptions.ConnectionClosedByBroker:
            logger.error("Connection closed by broker. Reconnecting...")
            time.sleep(5)
            cleanup_connection(connection)

        except KeyboardInterrupt:
            logger.info("Embedding consumer stopped by user")
            cleanup_connection(connection)
            break

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            time.sleep(5)
            cleanup_connection(connection)