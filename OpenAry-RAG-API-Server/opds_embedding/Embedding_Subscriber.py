import json
import os
import json
import ast
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
import urllib3
from opensearchpy import OpenSearch, RequestsHttpConnection
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http import models
from qdrant_client.http.models import Distance, VectorParams

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

if not os.path.exists("log"):
    os.makedirs("log")

logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)

f_format = logging.Formatter('[%(asctime)s][%(levelname)s|%(filename)s:%(lineno)s] --- %(message)s')

path = "log/preprocess.log"
file_handler = TimedRotatingFileHandler(path,encoding='utf-8',
                                   when="h",
                                   interval=1,
                                   backupCount=24)
file_handler.namer = lambda name: name + ".txt"
file_handler.setFormatter(f_format)

# Stream Handler 설정 (Windows 인코딩 문제 해결)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(f_format)
# Windows에서 UTF-8 출력을 위한 설정
if hasattr(stream_handler.stream, 'reconfigure'):
    try:
        stream_handler.stream.reconfigure(encoding='utf-8')
    except:
        pass

# Handler 추가
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

ENV = os.getenv('ENVIRONMENT', 'development')

if ENV == 'development':
    config_file = '../config/svc-set.debug.yaml'
else:
    config_file = '../config/svc-set.yaml'

# 설정 파일 존재 여부 확인
if not os.path.exists(config_file):
    logger.error(f"설정 파일을 찾을 수 없습니다: {config_file}")
    sys.exit(1)

logger.info(f"환경: {ENV}, 설정 파일: {config_file}")

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
# Windows에서 UTF-8 출력을 위한 설정
if hasattr(stream_handler.stream, 'reconfigure'):
    try:
        stream_handler.stream.reconfigure(encoding='utf-8')
    except:
        pass

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# 설정 값 가져오기
mongo_host = config['database']['mongodb']['mongo_host']
mongo_port = config['database']['mongodb']['mongo_port']
mongo_user = config['database']['mongodb']['mongo_user']
mongo_passwd = config['database']['mongodb']['mongo_passwd']
auth_source = config['database']['mongodb']['auth_source']

vector_postgres = config['database']['vector_db_postgres']
vector_opensearch = config['database']['vector_db_opensearch']
opds_system_db = config['database']['opds_system_db']
vector_qdrant = config['database']['vector_db_qdrant']

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

embedding_model = HuggingFaceEmbeddings(
    model_name=f'./embeddingmodel/{EMBEDDING_MODEL_ID}/',
    model_kwargs={'device': 'cpu'}
)


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

def get_opensearch_client():
    """OpenSearch 클라이언트를 생성합니다."""
    try:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        client = OpenSearch(
            hosts=[{'host': vector_opensearch['address'], 'port': vector_opensearch['port']}],
            http_auth=(vector_opensearch['id'], vector_opensearch['pwd']),
            http_compress=True,
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=30,
            retry_on_timeout=True,
            max_retries=3,
            connection_class=RequestsHttpConnection
        )
        
        # 연결 테스트
        info = client.info()
        logger.info(f"OpenSearch 연결 성공: {info.get('version', {}).get('number', 'unknown')}")
        return client
        
    except Exception as e:
        logger.error(f"OpenSearch 클라이언트 생성 오류: {str(e)}")
        return None

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


def get_qdrant_client():
    """Qdrant 클라이언트를 생성합니다."""
    try:
        # 설정에서 값 가져오기
        address = vector_qdrant['address']
        port = vector_qdrant['port']
        api_key = vector_qdrant['api-key']
        
        # 프로토콜 제거하여 순수 호스트명만 추출
        if address.startswith(('http://', 'https://')):
            # 프로토콜 제거 (http:// 또는 https://)
            host = address.split('//')[1].split(':')[0]
        else:
            host = address
        
        logger.info(f"Qdrant 연결 정보: 호스트={host}, 포트={port}")
        
        qdrant_client = QdrantClient(
            host=host,
            port=port,
            api_key=api_key,
            prefer_grpc=False,
            https=False,  # SSL 비활성화
            timeout=30
        )
        
        # 간단한 API 호출로 테스트
        collections = qdrant_client.get_collections()
        logger.info(f"Qdrant 연결 성공! 컬렉션 목록: {collections}")
        return qdrant_client

    except Exception as e:
        logger.error(f"Qdrant 클라이언트 생성 오류: {str(e)}")
        return None

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


def sentent_embedding(sentence, type="opensearch"):
    """문장 임베딩 함수"""
    if type == "qdrant":
        # Qdrant용 임베딩 - 딕셔너리 형태로 반환
        embedded_content = {"context_vector": embedding_model.embed_query(sentence)}
        return embedded_content
    elif type == "opensearch":
        # OpenSearch용 임베딩 
        embedded_content = embedding_model.embed_query(sentence)
        return embedded_content
    elif type == "pgvector":
        # PgVector용 임베딩
        embedded_content = embedding_model.embed_query(sentence)
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


def batch_insert_vectors_pgvector(user_code, vectors_data):
    """벡터 데이터 일괄 삽입"""
    if not vectors_data:
        return

    with get_postgres_connection() as conn:
        with conn.cursor() as cursor:
            # 새로운 데이터 구조에서 PgVector용 데이터 추출
            pgvector_data = []
            for item in vectors_data:
                pgvector_data.append((
                    item['doc_id'],
                    item['filename'],
                    item['text'],
                    item['pgvector_embedding']
                ))
            
            # 다중 행 삽입을 위한 쿼리 구성
            args_str = ','.join(cursor.mogrify("(%s, %s, %s, %s)", x).decode('utf-8') for x in pgvector_data)
            insert_query = f"INSERT INTO {user_code} (doc_id, source, text, vector) VALUES " + args_str
            cursor.execute(insert_query)
            conn.commit()


def batch_insert_vectors_opensearch(user_code, vectors_data):
    """OpenSearch에 벡터 데이터 일괄 삽입"""
    if not vectors_data:
        return
    
    opensearch_client = get_opensearch_client()
    if not opensearch_client:
        logger.error("OpenSearch 클라이언트를 생성할 수 없습니다.")
        return
    
    try:
        # 인덱스 이름은 user_code를 기반으로 생성
        index_name = f"vectors_{user_code.lower()}"
        
        # 인덱스가 존재하지 않으면 생성
        if not opensearch_client.indices.exists(index=index_name):
            index_body = {
                "settings": {
                    "index": {
                        "knn": True,
                        "knn.algo_param.ef_search": 100
                    }
                },
                "mappings": {
                    "properties": {
                        "doc_id": {"type": "keyword"},
                        "source": {"type": "text"},
                        "text": {"type": "text"},
                        "vector": {
                            "type": "knn_vector",
                            "dimension": 1024,  # BGE-M3 모델의 차원
                            "method": {
                                "name": "hnsw",
                                "space_type": "cosinesimil",
                                "engine": "lucene",
                                "parameters": {
                                    "ef_construction": 128,
                                    "m": 24
                                }
                            }
                        }
                    }
                }
            }
            opensearch_client.indices.create(index=index_name, body=index_body)
            logger.info(f"OpenSearch 인덱스 생성: {index_name}")
        
        # 벡터 데이터를 OpenSearch 형식으로 변환하여 일괄 삽입
        actions = []
        for item in vectors_data:
            doc_id = item['doc_id']
            source = item['filename']
            text = item['text']
            vector_str = item['opensearch_embedding']
            # 문자열로 저장된 벡터를 리스트로 변환
            try:
                vector_list = json.loads(vector_str)
                
            except Exception as e:
                logger.error(f"OpenSearch 벡터 변환 오류: {str(e)}")
                continue
                
            action = {
                "_index": index_name,
                "_id": f"{doc_id}_{hash(text)}",  # 고유 ID 생성
                "_source": {
                    "doc_id": doc_id,
                    "source": source,
                    "text": text,
                    "vector": vector_list
                }
            }
            actions.append(action)
        
        # 벌크 삽입 실행
        if actions:
            from opensearchpy.helpers import bulk
            bulk(opensearch_client, actions)
            logger.debug(f"OpenSearch에 {len(actions)}개 벡터 삽입 완료")
            
    except Exception as e:
        logger.error(f"OpenSearch 벡터 삽입 오류: {str(e)}")


def batch_insert_vectors_qdrant(user_code, vectors_data):
    """Qdrant에 벡터 데이터 일괄 삽입"""
    if not vectors_data:
        return
    
    qdrant_client = get_qdrant_client()
    if not qdrant_client:
        logger.error("Qdrant 클라이언트를 생성할 수 없습니다.")
        return
    
    try:
        # 컬렉션 이름은 user_code를 기반으로 생성
        collection_name = user_code
        
        # 컬렉션이 존재하지 않으면 생성
        try:
            qdrant_client.get_collection(collection_name)
        except Exception:
            # 컬렉션이 존재하지 않으면 생성
            qdrant_client.create_collection(
                collection_name=collection_name,
                vectors_config=VectorParams(size=1024, distance=Distance.COSINE)
            )
            logger.info(f"Qdrant 컬렉션 생성: {collection_name}")
        
        # 벡터 데이터를 Qdrant 형식으로 변환하여 일괄 삽입
        points = []
        point_id = int(time.time() * 1000000)  # 고유 ID 생성을 위한 타임스탬프 기반
        
        for item in vectors_data:
            try:
                doc_id = item['doc_id']
                source = item['filename']
                text = item['text']
                qdrant_embedding = item['qdrant_embedding']
                
                # Qdrant 임베딩에서 벡터 추출
                if isinstance(qdrant_embedding, dict) and 'context_vector' in qdrant_embedding:
                    vector_list = qdrant_embedding['context_vector']
                else:
                    logger.error(f"잘못된 Qdrant 임베딩 형식: {type(qdrant_embedding)}")
                    continue
                
                # 벡터가 올바른 형식인지 확인
                if not isinstance(vector_list, list) or len(vector_list) != 1024:
                    logger.error(f"잘못된 벡터 형식: 길이={len(vector_list) if isinstance(vector_list, list) else 'not list'}")
                    continue
                
                # Qdrant 포인트 생성
                point = models.PointStruct(
                    id=point_id,
                    vector=vector_list,
                    payload={
                        "doc_id": doc_id,
                        "source": source,
                        "text": text,
                    }
                )
                points.append(point)
                point_id += 1
                
            except Exception as e:
                logger.error(f"Qdrant 벡터 변환 오류: {str(e)}")
                continue
        
        # 벌크 삽입 실행
        if points:
            qdrant_client.upsert(
                collection_name=collection_name,
                points=points
            )
            logger.debug(f"Qdrant에 {len(points)}개 벡터 삽입 완료")
            
    except Exception as e:
        logger.error(f"Qdrant 벡터 삽입 오류: {str(e)}")


def delete_vectors_postgres(user_code, doc_id):
    """PostgreSQL에서 벡터 삭제"""
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
                logger.debug(f"PostgreSQL에서 doc_id {doc_id} 삭제 완료")


def delete_vectors_opensearch(user_code, doc_id):
    """OpenSearch에서 벡터 삭제"""
    opensearch_client = get_opensearch_client()
    if not opensearch_client:
        logger.error("OpenSearch 클라이언트를 생성할 수 없습니다.")
        return
    
    try:
        index_name = f"vectors_{user_code.lower()}"
        
        # 인덱스가 존재하는지 확인
        if not opensearch_client.indices.exists(index=index_name):
            logger.warning(f"OpenSearch 인덱스가 존재하지 않습니다: {index_name}")
            return
        
        # doc_id로 문서들 삭제
        delete_query = {
            "query": {
                "term": {
                    "doc_id": doc_id
                }
            }
        }
        
        response = opensearch_client.delete_by_query(index=index_name, body=delete_query)
        deleted_count = response.get('deleted', 0)
        logger.debug(f"OpenSearch에서 doc_id {doc_id}의 {deleted_count}개 문서 삭제 완료")
        
    except Exception as e:
        logger.error(f"OpenSearch 벡터 삭제 오류: {str(e)}")


def delete_vectors_qdrant(user_code, doc_id):
    """Qdrant에서 벡터 삭제"""
    qdrant_client = get_qdrant_client()
    if not qdrant_client:
        logger.error("Qdrant 클라이언트를 생성할 수 없습니다.")
        return
    
    try:
        collection_name = user_code
        
        # 컬렉션이 존재하는지 확인
        try:
            qdrant_client.get_collection(collection_name)
        except Exception:
            logger.warning(f"Qdrant 컬렉션이 존재하지 않습니다: {collection_name}")
            return
        
        # doc_id로 포인트들 삭제
        from qdrant_client.http.models import Filter, FieldCondition, MatchValue
        
        delete_filter = Filter(
            must=[
                FieldCondition(
                    key="doc_id",
                    match=MatchValue(value=doc_id)
                )
            ]
        )
        
        response = qdrant_client.delete(
            collection_name=collection_name,
            points_selector=delete_filter
        )
        
        logger.debug(f"Qdrant에서 doc_id {doc_id} 삭제 완료")
        
    except Exception as e:
        logger.error(f"Qdrant 벡터 삭제 오류: {str(e)}")


def batch_insert_vectors_unified(user_code, vectors_data):
    batch_insert_vectors_pgvector(user_code, vectors_data)
    batch_insert_vectors_opensearch(user_code, vectors_data)
    batch_insert_vectors_qdrant(user_code, vectors_data)


def delete_vectors_unified(user_code, doc_id):
    """통합 벡터 삭제 함수 - 설정에 따라 적절한 DB에서 삭제"""
    delete_vectors_postgres(user_code, doc_id)
    delete_vectors_opensearch(user_code, doc_id)
    delete_vectors_qdrant(user_code, doc_id)

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

        # 벡터 DB에서 기존 데이터 삭제 (통합 함수 사용)
        delete_vectors_unified(user_code, doc_id)

        logger.debug(f"append user {user_code} file id {doc_id}")

        # 텍스트 청크로 분할
        chunk_tokens = nltk_text_spliter.split_text(clean_doc)
        len_chunk = len(chunk_tokens)

        # 벡터 삽입을 위한 배치 처리 (배치 크기: 50)
        batch_size = 50
        vectors_batch = []

        for ci, clean_text in enumerate(chunk_tokens, 1):
            try:
                # 특수 문자 처리
                clean_text = clean_text.encode().decode().replace("\x00", "")
                clean_text = clean_text.replace("'", "''")

                # 각 벡터 DB에 맞는 임베딩 생성
                pgvector_embedding = sentent_embedding(clean_text, type="pgvector")  # PgVector, OpenSearch용
                opensearch_embedding = sentent_embedding(clean_text, type="opensearch")  # PgVector, OpenSearch용
                qdrant_embedding = sentent_embedding(clean_text, type="qdrant")   # Qdrant용

                # 배치에 추가 (각각의 임베딩 포함)
                vectors_batch.append({
                    'doc_id': doc_id,
                    'filename': filename,
                    'text': clean_text,
                    'pgvector_embedding': str(pgvector_embedding),
                    'qdrant_embedding': qdrant_embedding,
                    'opensearch_embedding': str(opensearch_embedding)
                })

                # 배치 크기에 도달하거나 마지막 항목이면 삽입
                if len(vectors_batch) >= batch_size or ci == len_chunk:
                    batch_insert_vectors_unified(user_code, vectors_batch)
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