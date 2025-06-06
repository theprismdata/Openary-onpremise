import json
import os
import time
import pymongo
import pymysql
import yaml
import pika
import logging
from logging.handlers import TimedRotatingFileHandler
import re
from datetime import datetime
from pytz import timezone
from langchain_core.documents import Document
from langchain_core.prompts import PromptTemplate
from langchain_community.chat_models import ChatOpenAI
from langchain.chains.summarize import load_summarize_chain
from check_token import token_counter
from functools import lru_cache
from contextlib import contextmanager

print("build:2025-02-26#11:30")

# 환경 설정 및 설정 파일 로드
ENV = os.getenv('ENVIRONMENT', 'development')
config_file = f'../config/svc-set.{"debug." if ENV == "development" else ""}yaml'

# 설정 파일은 한 번만 로드
with open(config_file) as f:
    config = yaml.load(f, Loader=yaml.FullLoader)

# 로깅 설정
logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)

if not os.path.exists("log"):
    os.makedirs("log")

f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

path = "log/summary.log"
handler = TimedRotatingFileHandler(path,
                                   when="h",
                                   interval=1,
                                   backupCount=24)
handler.namer = lambda name: name + ".txt"
handler.setFormatter(f_format)
logger.addHandler(handler)

# 설정 값 추출
mqtt_info = config['mqtt']
mqtt_id = mqtt_info['id']
mqtt_pwd = mqtt_info['pwd']
mqtt_address = mqtt_info['address']
mqtt_port = mqtt_info['port']
mqtt_virtualhost = mqtt_info['virtualhost']

mongo_host = config['database']['mongodb']['mongo_host']
mongo_port = config['database']['mongodb']['mongo_port']
mongo_user = config['database']['mongodb']['mongo_user']
mongo_passwd = config['database']['mongodb']['mongo_passwd']
auth_source = config['database']['mongodb']['auth_source']

RABBITMQ_SVC_QUEUE = config['RABBITMQ_SVC_QUEUE']

OPENAI_API_KEY = config['langmodel']['API']['OpenAI']['apikey']
OPENAI_CHAT_MODEL = config['langmodel']['API']['OpenAI']['chat_model']

opds_system_db = config['database']['opds_system_db']

mongo_uri = f"mongodb://{mongo_user}:{mongo_passwd}@{mongo_host}:{mongo_port}/?authSource={auth_source}&authMechanism=SCRAM-SHA-1"

# 프롬프트 템플릿 설정
prompt_template = """다음의 내용을 간결하게 요약해줘:
{text}
간결 요약:"""
prompt = PromptTemplate.from_template(prompt_template)

refine_template = (
    "Your job is to produce a final summary\n"
    "We have provided an existing summary up to a certain point: {existing_answer}\n"
    "We have the opportunity to refine the existing summary"
    "(only if needed) with some more context below.\n"
    "------------\n"
    "{text}\n"
    "------------\n"
    "Given the new context, refine the original summary in Korean"
    "If the context isn't useful, return the original summary."
)
refine_prompt = PromptTemplate.from_template(refine_template)


# 데이터베이스 연결 관리를 위한 컨텍스트 매니저들
@contextmanager
def get_mongo_connection():
    """MongoDB 연결 컨텍스트 매니저"""
    client = pymongo.MongoClient(mongo_uri, maxPoolSize=10)
    try:
        yield client[auth_source]
    finally:
        client.close()


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


# LLM Chain 생성 (캐싱 적용)
@lru_cache(maxsize=1)
def get_summary_chain():
    """요약 체인 생성 (캐싱 적용)"""
    llm = ChatOpenAI(
        openai_api_key=OPENAI_API_KEY,
        temperature=0,
        model_name=OPENAI_CHAT_MODEL,
        streaming=True,
    )

    chain = load_summarize_chain(
        llm=llm,
        chain_type="refine",
        question_prompt=prompt,
        refine_prompt=refine_prompt,
        return_intermediate_steps=True,
        input_key="input_documents",
        output_key="output_text",
    )
    return chain


def update_document_status(doc_id, summary, status="complete"):
    """문서 상태 업데이트"""
    with get_mysql_connection() as conn:
        with conn.cursor() as cs:
            end_time = datetime.now(timezone('Asia/Seoul')).strftime("%Y-%m-%d %H:%M:%S.%f")

            # 특수 문자 제거 및 이스케이프 처리
            summary = re.sub('[-=+,#/\?:^$.@*\"※~&%ㆍ!』\\' |\(\)\[\]\ < \ > `\'…》]', '', summary)
            summary = summary.replace('"', '\\"')  # 따옴표 이스케이프

            sql = f"""UPDATE {opds_system_db["database"]}.tb_llm_doc 
                      SET summary = "{summary}", 
                          process_end = "{end_time}", 
                          status = "{status}" 
                      WHERE id = {doc_id}"""
            try:
                cs.execute(sql)
                conn.commit()
                logger.debug(f"Updated document status for doc_id: {doc_id}")
            except Exception as e:
                logger.error(f"SQL error when updating document status: {str(e)}")
                logger.error(sql)
                conn.rollback()


def update_mongo_summary_status(user_code, file_name, doc_id, status="finish"):
    """MongoDB 요약 상태 업데이트"""
    with get_mongo_connection() as mongodb_genai:
        try:
            mongodb_genai[user_code].update_one(
                {"filename": file_name, "id": doc_id},
                {"$set": {"summary": status}}
            )
            logger.debug(f"Updated MongoDB summary status for doc_id: {doc_id}")
        except Exception as e:
            logger.error(f"MongoDB error when updating summary status: {str(e)}")


def process_document_summary(user_code, doc_id, file_name, clean_doc):
    """문서 요약 처리"""
    if clean_doc is None or len(clean_doc) == 0:
        # 원본 추출 오류 처리
        summary_result = "원본 추출 오류"
        update_document_status(doc_id, summary_result)
        update_mongo_summary_status(user_code, file_name, doc_id)
        return

    # 문서 내용 제한 (토큰 제한을 위해)
    clean_doc = clean_doc[:1000]

    # 토큰 수 계산
    num_tokens = token_counter(clean_doc, OPENAI_CHAT_MODEL)
    logger.info(f"User {user_code} File Index {doc_id} Summary request token length: {num_tokens}")

    try:
        # LangChain 문서 생성
        lc_doc = [Document(page_content=clean_doc, metadata={"source": file_name})]

        # 요약 체인 실행
        logger.debug(f"User {user_code} File Index {doc_id} in LLM summary")
        chain = get_summary_chain()
        result = chain.invoke({"input_documents": lc_doc}, return_only_outputs=False)

        # 결과 처리
        summary_result = result["output_text"]
        logger.debug(f"Summary result: {summary_result[:100]}...")

        # 상태 업데이트
        update_document_status(doc_id, summary_result)
        update_mongo_summary_status(user_code, file_name, doc_id)

    except Exception as e:
        logger.error(f"Error during summary generation: {str(e)}")
        # 오류 발생 시 기본 메시지로 상태 업데이트
        summary_result = "요약 처리 중 오류가 발생했습니다."
        update_document_status(doc_id, summary_result, status="error")
        update_mongo_summary_status(user_code, file_name, doc_id, status="error")


def wait_mq_signal(ch, method, properties, body):
    """메시지 큐 메시지 처리 콜백"""
    body = body.decode('utf-8')
    msg_json = json.loads(body)
    logger.info("SUMMARY SUBSCRIBE")
    logger.info(msg_json)

    try:
        # 메시지에서 정보 추출
        user_email = msg_json['user_email']
        user_code = msg_json['user_code']
        doc_id = msg_json['doc_id']
        file_name = msg_json['file_name']

        # MongoDB에서 문서 정보 조회
        with get_mongo_connection() as mongodb_genai:
            doc = mongodb_genai[user_code].find_one(
                {
                    "cleansing": "finish",
                    "summary": "ready",
                    "id": doc_id
                }
            )

        if not doc:
            logger.warning(f"Document not found or not ready for summary: {doc_id}")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        # 문서 요약 처리
        clean_doc = doc.get('clean_doc')
        process_document_summary(user_code, doc_id, file_name, clean_doc)

        # 메시지 처리 완료 승인
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")
        # 오류 발생 시에도 메시지 승인 (무한 재시도 방지)
        ch.basic_ack(delivery_tag=method.delivery_tag)


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
            print("Summary consumer start")
            logger.info("Summary consumer start")

            connection = create_connection()
            OPDS_SUMMARY_REQ_Channel = connection.channel()
            OPDS_SUMMARY_REQ_Q = RABBITMQ_SVC_QUEUE['SUMMARY_Q_NAME']
            OPDS_SUMMARY_REQ_Channel.queue_declare(queue=OPDS_SUMMARY_REQ_Q)
            OPDS_SUMMARY_REQ_Channel.basic_qos(prefetch_count=1)  # 한 번에 하나의 메시지만 처리

            OPDS_SUMMARY_REQ_Channel.basic_consume(
                queue=OPDS_SUMMARY_REQ_Q,
                on_message_callback=wait_mq_signal,
                auto_ack=False
            )

            OPDS_SUMMARY_REQ_Channel.start_consuming()

        except pika.exceptions.StreamLostError:
            logger.error("Connection lost. Reconnecting...")
            time.sleep(5)
            cleanup_connection(connection)

        except pika.exceptions.ConnectionClosedByBroker:
            logger.error("Connection closed by broker. Reconnecting...")
            time.sleep(5)
            cleanup_connection(connection)

        except KeyboardInterrupt:
            logger.info("Summary consumer stopped by user")
            cleanup_connection(connection)
            break

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            time.sleep(5)
            cleanup_connection(connection)