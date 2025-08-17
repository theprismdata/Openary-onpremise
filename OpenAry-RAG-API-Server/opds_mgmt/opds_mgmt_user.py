import flask
import yaml
import psycopg2
import pymysql
import pandas as pd
import os
from logging.handlers import TimedRotatingFileHandler
from pgvector.psycopg2 import register_vector
import logging
import hashlib
from minio import Minio
import flask
from flask import Flask, jsonify, request
from flask_restx import Api, Resource, fields, reqparse, Namespace
from flask_cors import CORS
import sys
from opensearchpy import OpenSearch, RequestsHttpConnection
import requests
import json
import time
import urllib3
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http import models
from qdrant_client.http.models import Distance, VectorParams

if not os.path.exists("log"):
    os.makedirs("log")

logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)

f_format = logging.Formatter('[%(asctime)s][%(levelname)s|%(filename)s:%(lineno)s] --- %(message)s')

path = "log/opds_mgmt_user.log"
file_handler = TimedRotatingFileHandler(path,encoding='utf-8',
                                   when="h",
                                   interval=1,
                                   backupCount=24)
file_handler.namer = lambda name: name + ".txt"
file_handler.setFormatter(f_format)

# Stream Handler 설정
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(f_format)

# Handler 추가
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# Pycharm에서 수행시.
# module : flask
# run
# NUNBUFFERED=1;FLASK_APP=opds_mgmt_user.py;FLASK_ENV=dev

ENV = os.getenv('ENVIRONMENT', 'development')

logger.info(f"ENV: {ENV}")

if ENV == 'development':
    config_file = '../config/svc-set.debug.yaml'
else:
    config_file = '../config/svc-set.yaml'

if not os.path.exists(config_file):
    logger.error(f"설정 파일을 찾을 수 없습니다: {config_file}")
    sys.exit(1)

logger.info(f"환경: {ENV}, 설정 파일: {config_file}")

with open(config_file) as f:
    config = yaml.load(f, Loader=yaml.FullLoader)

app = flask.Flask(__name__)
api = Api(app,
          version='1.0',
          title='OpenAry System Mgmt Document',
          description='', doc="/api-docs")

Welcome_NS = Namespace(name="mgmt", description="")
api.add_namespace(Welcome_NS)

UpdatePWD_NS = Namespace(name="mgmt", description="")
update_pwd_model = UpdatePWD_NS.model('update_pwd_field', {  # Model 객체 생성
    'email': fields.String(description='email', required=True, example="guest@abc.cc"),
    'passwd': fields.String(description='current passwd', required=True, example="xxxx"),
    'new_passwd': fields.String(description='new passwd', required=True, example="xxxx")
})
api.add_namespace(UpdatePWD_NS)

UserCode_NS = Namespace(name="mgmt", description="")
user_email_model = UserCode_NS.model('email_field', {  # Model 객체 생성
    'email': fields.String(description='email', required=True, example="theprismdata@gmail.com"),
})
api.add_namespace(UserCode_NS)

Append_UserField_NS = Namespace(name="mgmt", description="")
add_user_model = Append_UserField_NS.model('add_user_field', {  # Model 객체 생성
    'email': fields.String(description='email', required=True, example="guest@abc.cc"),
    'new_passwd': fields.String(description='new passwd', required=True, example="xxxx")
})
api.add_namespace(Append_UserField_NS)

Delete_User_NS = Namespace(name="mgmt", description="")
delete_user_model = Delete_User_NS.model('delete_user_field', {  # Model 객체 생성
    'email': fields.String(description='email', required=True, example="guest@abc.cc"),
    'passwd': fields.String(description='new passwd', required=True, example="xxxx")
})
api.add_namespace(Delete_User_NS)

CORS(app)  # 모든 도메인 허용

rest_config = config['mgmt_rest_config']
vector_postgres = config['database']['vector_db_postgres']
vector_opensearch = config['database']['vector_db_opensearch']
opds_system_db = config['database']['opds_system_db']
vector_qdrant = config['database']['vector_db_qdrant']

# MongoDB 설정 (선택사항)
try:
    mongo_host = config['database']['mongodb']['mongo_host']
    mongo_port = config['database']['mongodb']['mongo_port']
    mongo_user = config['database']['mongodb']['mongo_user']
    mongo_passwd = config['database']['mongodb']['mongo_passwd']
    auth_source = config['database']['mongodb']['auth_source']
except KeyError:
    logger.info("MongoDB 설정이 없습니다. MongoDB 기능은 비활성화됩니다.")
    mongo_host = None

minio_info = config['minio']
minio_address = minio_info['address']
accesskey = minio_info['accesskey']
secretkey = minio_info['secretkey']

def make_sha_email(email_addr: str):
    h = hashlib.sha1()
    h.update(email_addr.encode())
    enc_email = h.hexdigest()
    print(enc_email)
    enc_email = "e"+enc_email
    return enc_email

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
        logger.info(f"✅ Qdrant 연결 성공! 컬렉션 목록: {collections}")
        return qdrant_client

    except Exception as e:
        logger.error(f"Qdrant 클라이언트 생성 오류: {str(e)}")
        return None

def create_qdrant_collection(user_code: str):
    """사용자별 Qdrant 컬렉션을 생성합니다."""
    max_retries = 3
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            client = get_qdrant_client()
            if client is None:
                logger.error(f"Qdrant 클라이언트 생성 실패 (시도 {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                return False, "Qdrant 클라이언트 생성 실패"
            
            collection_name = user_code.lower()  # 컬렉션명은 소문자로
            
            # BGE-M3 모델의 실제 차원
            embedding_dimension = 1024
            logger.info(f"사용할 임베딩 차원: {embedding_dimension}")
            
            # 컬렉션이 이미 존재하는지 확인
            try:
                collection_info = client.get_collection(collection_name)
                logger.info(f"컬렉션 {collection_name}가 이미 존재합니다.")
                return True, "컬렉션이 이미 존재함"
            except Exception:
                # 컬렉션이 존재하지 않으면 생성
                pass
            
            # 컬렉션 생성
            client.create_collection(
                collection_name=collection_name,
                vectors_config=VectorParams(
                    size=embedding_dimension,
                    distance=Distance.COSINE
                )
            )
            
            logger.info(f"✅ Qdrant 컬렉션 생성 성공: {collection_name}")
            logger.info(f"   - 벡터 차원: {embedding_dimension}")
            logger.info(f"   - 거리 측정: COSINE")
            return True, "컬렉션 생성 성공"
            
        except Exception as e:
            logger.error(f"Qdrant 컬렉션 생성 오류 (시도 {attempt + 1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                logger.info(f"{retry_delay}초 후 재시도...")
                time.sleep(retry_delay)
                retry_delay *= 2  # 지수 백오프
            else:
                return False, str(e)

def delete_qdrant_collection(user_code: str):
    """사용자별 Qdrant 컬렉션을 삭제합니다."""
    try:
        client = get_qdrant_client()
        if client is None:
            return False, "Qdrant 클라이언트 생성 실패"
        
        collection_name = user_code.lower()  # 컬렉션명은 소문자로
        
        # 컬렉션이 존재하는지 확인
        try:
            client.get_collection(collection_name)
        except Exception:
            logger.info(f"컬렉션 {collection_name}가 존재하지 않습니다.")
            return True, "컬렉션이 존재하지 않음"
        
        # 컬렉션 삭제
        client.delete_collection(collection_name)
        logger.info(f"✅ Qdrant 컬렉션 삭제 성공: {collection_name}")
        return True, "컬렉션 삭제 성공"
        
    except Exception as e:
        logger.error(f"Qdrant 컬렉션 삭제 오류: {str(e)}")
        return False, str(e)

def test_qdrant_connection():
    """Qdrant 연결을 테스트합니다."""
    try:
        logger.info(f"Qdrant 연결 테스트: {vector_qdrant['address']}:{vector_qdrant['port']}")
        
        client = get_qdrant_client()
        if client:
            collections = client.get_collections()
            logger.info(f"컬렉션 목록: {collections}")
            return True, "연결 성공"
        else:
            return False, "클라이언트 생성 실패"
            
    except Exception as e:
        logger.error(f"Qdrant 연결 테스트 실패: {str(e)}")
        return False, str(e)

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
        logger.info(f"✅ OpenSearch 연결 성공: {info.get('version', {}).get('number', 'unknown')}")
        return client
        
    except Exception as e:
        logger.error(f"OpenSearch 클라이언트 생성 오류: {str(e)}")
        return None

def get_bge_m3_dimension():
    """BGE-M3 모델의 실제 차원을 동적으로 감지합니다."""
    try:
        model_name = "BAAI/bge-m3"
        test_model = SentenceTransformer(model_name)
        test_embedding = test_model.encode("테스트", convert_to_numpy=True)
        actual_dimension = len(test_embedding)
        logger.info(f"BGE-M3 모델 실제 차원: {actual_dimension}")
        return actual_dimension
    except Exception as e:
        logger.warning(f"BGE-M3 차원 감지 실패, 기본값 1024 사용: {str(e)}")
        return 1024

def create_opensearch_index(user_code: str):
    """사용자별 OpenSearch 인덱스를 생성합니다."""
    max_retries = 3
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            client = get_opensearch_client()
            if client is None:
                logger.error(f"OpenSearch 클라이언트 생성 실패 (시도 {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                return False, "OpenSearch 클라이언트 생성 실패"
            
            index_name = user_code.lower()  # 인덱스명은 소문자로
            
            # BGE-M3 모델의 실제 차원 감지
            embedding_dimension = 1024 #get_bge_m3_dimension()
            logger.info(f"사용할 임베딩 차원: {embedding_dimension}")
            
            # 인덱스 매핑 설정 (동적 차원 적용)
            index_mapping = {
                "settings": {
                    "index": {
                        "knn": True,
                        "knn.algo_param.ef_search": 512,
                        "number_of_shards": 1,
                        "number_of_replicas": 0,
                        "refresh_interval": "30s"
                    }
                },
                "mappings": {
                    "properties": {
                        "source": {
                            "type": "text"
                        },
                        "text": {
                            "type": "text",
                            "analyzer": "standard"
                        },
                        "vector": {
                            "type": "knn_vector",
                            "dimension": embedding_dimension,
                            "method": {
                                "name": "hnsw",
                                "space_type": "cosinesimil",
                                "engine": "nmslib",
                                "parameters": {
                                    "ef_construction": 200,
                                    "m": 24
                                }
                            }
                        },
                        "doc_id": {
                            "type": "integer"
                        }
                    }
                }
            }
            
            # 인덱스가 이미 존재하는지 확인
            if client.indices.exists(index=index_name):
                # 기존 인덱스 매핑 확인
                try:
                    mapping = client.indices.get_mapping(index=index_name)
                    existing_dimension = mapping[index_name]['mappings']['properties']['vector']['dimension']
                    
                    if existing_dimension != embedding_dimension:
                        logger.warning(f"기존 인덱스 차원({existing_dimension})과 현재 모델 차원({embedding_dimension})이 다릅니다.")
                        logger.warning("인덱스를 재생성하려면 수동으로 삭제 후 다시 생성하세요.")
                    else:
                        logger.info(f"인덱스 {index_name}가 이미 존재하고 차원이 일치합니다.")
                except Exception as mapping_error:
                    logger.warning(f"기존 인덱스 매핑 확인 실패: {str(mapping_error)}")
                
                return True, "인덱스가 이미 존재함"
            
            # 인덱스 생성
            response = client.indices.create(index=index_name, body=index_mapping)
            logger.info(f"✅ OpenSearch 인덱스 생성 성공: {index_name}")
            logger.info(f"   - 벡터 차원: {embedding_dimension}")
            logger.info(f"   - 벡터 타입: knn_vector")
            logger.info(f"   - 알고리즘: HNSW (nmslib)")
            logger.info(f"   - 응답: {response.get('acknowledged', False)}")
            return True, "인덱스 생성 성공"
            
        except Exception as e:
            logger.error(f"OpenSearch 인덱스 생성 오류 (시도 {attempt + 1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                logger.info(f"{retry_delay}초 후 재시도...")
                time.sleep(retry_delay)
                retry_delay *= 2  # 지수 백오프
            else:
                return False, str(e)

def delete_opensearch_index(user_code: str):
    """사용자별 OpenSearch 인덱스를 삭제합니다."""
    try:
        client = get_opensearch_client()
        if client is None:
            return False, "OpenSearch 클라이언트 생성 실패"
        
        index_name = user_code.lower()  # 인덱스명은 소문자로
        
        # 인덱스가 존재하는지 확인
        if not client.indices.exists(index=index_name):
            logger.info(f"인덱스 {index_name}가 존재하지 않습니다.")
            return True, "인덱스가 존재하지 않음"
        
        # 인덱스 삭제
        response = client.indices.delete(index=index_name)
        logger.info(f"OpenSearch 인덱스 삭제 성공: {index_name}")
        return True, "인덱스 삭제 성공"
        
    except Exception as e:
        logger.error(f"OpenSearch 인덱스 삭제 오류: {str(e)}")
        return False, str(e)

def test_opensearch_connection():
    """OpenSearch 연결을 테스트합니다."""
    try:
        logger.info(f"OpenSearch 연결 테스트: {vector_opensearch['address']}:{vector_opensearch['port']}")
        
        client = get_opensearch_client()
        if client:
            health = client.cluster.health()
            logger.info(f"클러스터 상태: {health.get('status', 'unknown')}")
            return True, "연결 성공"
        else:
            return False, "클라이언트 생성 실패"
            
    except Exception as e:
        logger.error(f"OpenSearch 연결 테스트 실패: {str(e)}")
        return False, str(e)

def get_usercode_by_username(input_user: str):
    opds_sysdb_conn = pymysql.connect(
        user=opds_system_db["id"],
        password=opds_system_db["pwd"],
        database=opds_system_db["database"],
        host=opds_system_db["address"],
        port=opds_system_db["port"]
    )
    try:
        sql = f'SELECT `id`, user_code FROM tb_user WHERE email="{input_user}"'  # 대상 파일 선택
        cs = opds_sysdb_conn.cursor()
        cs.execute(sql)
        rs = cs.fetchall()
        user_name_df = pd.DataFrame(rs, columns=['id', 'user_code'])
        cs.close()
        opds_sysdb_conn.close()

        if user_name_df.shape[0] == 1:
            user_code = user_name_df.iloc[0].to_dict()["user_code"]
            return 0, user_code
        else:
            return 1, None
    except Exception as e:
        return -1, str(e)

def check_exist_by_username(input_user: str, input_password: str):
    opds_sysdb_conn = pymysql.connect(
        user=opds_system_db["id"],
        password=opds_system_db["pwd"],
        database=opds_system_db["database"],
        host=opds_system_db["address"],
        port=opds_system_db["port"]
    )
    sql = f'SELECT `id`, email, password FROM tb_user WHERE email="{input_user}"'  # 대상 파일 선택
    cs = opds_sysdb_conn.cursor()
    cs.execute(sql)
    rs = cs.fetchall()
    user_name_df = pd.DataFrame(rs, columns=['id', 'name', 'password'])
    cs.close()
    opds_sysdb_conn.close()

    if user_name_df.shape[0] == 1:
        user_pwd = user_name_df.iloc[0].to_dict()
        rdb_password = user_pwd["password"]
        h = hashlib.sha512()
        h.update(input_password.encode())
        desc_passwd = h.hexdigest()
        if desc_passwd == rdb_password:
            return 0  # 사용자 암호 인증 완료
        else:
            return -1  # 암호 오류
    else:
        return 1  # 해당 사용자 없음.

def check_exist_by_email(input_email: str, input_password: str):
    try:
        opds_sysdb_conn = pymysql.connect(
            user=opds_system_db["id"],
            password=opds_system_db["pwd"],
            database=opds_system_db["database"],
            host=opds_system_db["address"],
            port=opds_system_db["port"]
        )
        sql = f'SELECT `id`, password FROM tb_user WHERE email="{input_email}"'  # 대상 파일 선택
        cs = opds_sysdb_conn.cursor()
        cs.execute(sql)
        rs = cs.fetchall()
        user_name_df = pd.DataFrame(rs, columns=['id', 'password'])
        cs.close()
        opds_sysdb_conn.close()

        if user_name_df.shape[0] == 1:
            user_pwd = user_name_df.iloc[0].to_dict()
            rdb_password = user_pwd["password"]
            h = hashlib.sha512()
            h.update(input_password.encode())
            desc_passwd = h.hexdigest()
            if desc_passwd == rdb_password:
                return 0, None  #사용자 암호 인증 완료
            else:
                return -1, "Password error"  # 암호 오류
        else:
            return 1, "No user"  # 해당 사용자 없음.
    except Exception as e:
        return -2, f"DB Error {str(e)}"  # DB오류

def build_actual_response(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "*")
    response.headers.add('Access-Control-Allow-Methods', "*")
    return response

"""
MariaDB table 생성 쿼리
CREATE TABLE `tb_user` (
  `id`  BIGINT auto_increment NOT NULL,
  `password` varchar(256) DEFAULT NULL COMMENT '비밀번호',
  `email` varchar(128) DEFAULT NULL COMMENT '이메일',
  `state` varchar(10) DEFAULT 'ACTIVE' COMMENT ' 상태 ACTIVE/INACTIVE',
  `wdate` datetime DEFAULT current_timestamp() COMMENT '생성일시',
  `udate` datetime DEFAULT current_timestamp() COMMENT '업데이트일시',
  `role` varchar(128) DEFAULT 'USER' COMMENT '사용자구분(USER/ADMIN/OPERATOR)',
  `lang` varchar(10) DEFAULT 'en' COMMENT '적용언어',
  `user_code` varchar(100) DEFAULT NULL,
  CONSTRAINT CUSTOMER_PK PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
"""

@Welcome_NS.route('/')
@Welcome_NS.response(400, 'BadRequest')
@Welcome_NS.response(500, 'Internal Server Error')
@Welcome_NS.response(503, 'Service Unavailable')
# test api
class Intro(Resource):
    def post(self):
        """
        Welcome message
        """
        return 'Hello~ This is OPenDocuSea Management System'

@Delete_User_NS.route('/delete_user')
@Delete_User_NS.response(400, 'BadRequest')
@Delete_User_NS.response(500, 'Internal Server Error')
@Delete_User_NS.response(503, 'Service Unavailable')
# test api
class DeleteUser(Resource):
    @UpdatePWD_NS.expect(delete_user_model)
    def post(self):
        """
        user 삭제
        :param
            email : 사용자 email
            passwrd : 사용자 암호
        :return:
        0 : 정상
        1 : 사용자가 없는 경우
        -1 : 사용자 제거 오류
        """
        param = request.json
        print(param)
        logger.debug(f"{param}")
        email = param["email"]
        passwd = param["passwd"]

        auth_status, msg = check_exist_by_email(input_email=email, input_password=passwd)
        if auth_status == 0:  # 사용자가 있는 경우
            auth_status, msg = self.delete_user(email=email)
            if auth_status == 0:
                json_rtn = {"auth": True,
                            "status": f"ok"}
                logger.debug(f"rtn : {json_rtn}")
                return build_actual_response(jsonify(json_rtn))
            else:
                json_rtn = {"auth": True,
                            "status": f"{msg}"}
                logger.debug(f"rtn : {json_rtn}")
                return json_rtn, 401
        elif auth_status == 1:
            json_rtn = {"auth": False,
                        "status": f"No user"}
            logger.debug(f"rtn : {json_rtn}")
            return json_rtn, 401
        elif auth_status == -1:
            json_rtn = {"auth": False,
                        "status": f"Password error"}
            logger.debug(f"rtn : {json_rtn}")
            return json_rtn, 403


    def delete_user(self, email):
        """
        user remove from mariadb, minio, pgvector, opensearch
        :param email:

        :return:
        """
        mail_sha_code = make_sha_email(email)
        
        try:
            mariadb_conn = pymysql.connect(
                user=opds_system_db["id"],
                password=opds_system_db["pwd"],
                database=opds_system_db["database"],
                host=opds_system_db["address"],
                port=opds_system_db["port"]
            )
            cs = mariadb_conn.cursor()
            sql = f"DELETE FROM tb_user WHERE email='{email}'"
            cs.execute(sql)
            mariadb_conn.commit()
            mariadb_conn.close()
        except Exception as e:
            print('Mgmt Query critical error')
            print(str(e))
            return -1, str(e)

        try:
            minio_client = Minio(minio_address,
                                 access_key=accesskey,
                                 secret_key=secretkey, secure=False)
            minio_client.remove_bucket(mail_sha_code)
        except Exception as e:
            print('Minio critical error')
            print(str(e))
            return -1, str(e)

        try:
            vector_db = psycopg2.connect(host=vector_postgres['address'],
                                         dbname=vector_postgres['database'],
                                         user=vector_postgres['id'],
                                         password=vector_postgres['pwd'],
                                         port=vector_postgres['port'])
            create_table_sql = f'''DROP TABLE public."{mail_sha_code}"'''
            vt_cs = vector_db.cursor()
            print(create_table_sql)
            vt_cs.execute(create_table_sql)
            vector_db.commit()
            vector_db.close()
        except Exception as e:
            logger.error(str(e))
            print('PGVector Connection critical error')
            print(str(e))
            return -1, str(e)
        
        # OpenSearch 인덱스 삭제 (선택사항)
        try:
            success, msg = delete_opensearch_index(mail_sha_code)
            if success:
                logger.info(f"OpenSearch 인덱스 삭제 성공: {mail_sha_code}")
            else:
                logger.warning(f"OpenSearch 인덱스 삭제 실패하지만 계속 진행: {msg}")
        except Exception as e:
            logger.warning(f"OpenSearch 오류 발생하지만 계속 진행: {str(e)}")
        
        # Qdrant 컬렉션 삭제 (선택사항)
        try:
            success, msg = delete_qdrant_collection(mail_sha_code)
            if success:
                logger.info(f"Qdrant 컬렉션 삭제 성공: {mail_sha_code}")
            else:
                logger.warning(f"Qdrant 컬렉션 삭제 실패하지만 계속 진행: {msg}")
        except Exception as e:
            logger.warning(f"Qdrant 오류 발생하지만 계속 진행: {str(e)}")
            
        return 0, None

@UpdatePWD_NS.route('/update_password')
@UpdatePWD_NS.response(400, 'BadRequest')
@UpdatePWD_NS.response(500, 'Internal Server Error')
@UpdatePWD_NS.response(503, 'Service Unavailable')
class UpdatePassword(Resource):
    @UpdatePWD_NS.expect(update_pwd_model)
    def post(self):
        """
        사용자의 암호를 변경합니다.
        :param
            email : 사용자 email
            passwrd : 이전 사용자 암호
            new_passwd : 새로운 사용자 암호
        :return:
        성공할 경우 {auth: True, "status":"ok"}
        오류 발생시 {auth: False, "status":"User info is incorrect"}
        """
        logger.debug(f"update_password:{request}")
        param = request.json
        print(param)
        logger.debug(f"{param}")
        email = param["email"]
        passwd = param["passwd"]
        new_passwd = param["new_passwd"]
        status, msg = self.update_password(user_email=email, user_passwd=passwd,
                                      new_passwd=new_passwd)
        if status != 0:
            json_rtn = {"auth": False,
                        "status": f"User info is incorrect {msg}"}
            logger.debug(f"rtn : {json_rtn}")
            return json_rtn, 403
        else:
            json_rtn = {"auth": True,
                        "status": "ok"}
            logger.debug(f"rtn : {json_rtn}")
            print(f"rtn : {json_rtn}")
            return build_actual_response(jsonify(json_rtn))

    def update_password(self, user_email, user_passwd, new_passwd):
        auth_status, _ = check_exist_by_email(input_email=user_email, input_password=user_passwd)
        err_msg = ''
        if auth_status == 0:  # 사용자가 있는 경우
            try:
                mariadb_conn = pymysql.connect(
                    user=opds_system_db["id"],
                    password=opds_system_db["pwd"],
                    database=opds_system_db["database"],
                    host=opds_system_db["address"],
                    port=opds_system_db["port"]
                )
                cs = mariadb_conn.cursor()

                h = hashlib.sha512()
                h.update(new_passwd.encode())
                encode_passwd = h.hexdigest()
                sql = f"UPDATE tb_user SET password='{encode_passwd}' WHERE email='{user_email}'"
                cs.execute(sql)
                mariadb_conn.commit()

                mariadb_conn.close()
            except Exception as e:
                logger.error(str(e))
                print('Mgmt DB Connection critical error')
                print(str(e))
                return -1, str(e)
            return 0, None
        else:
            return -1, err_msg

@UserCode_NS.route('/sync_user')
@UserCode_NS.response(400, 'BadRequest')
@UserCode_NS.response(500, 'Internal Server Error')
@UserCode_NS.response(503, 'Service Unavailable')
class SyncUser(Resource):
    @UserCode_NS.expect(user_email_model)
    def post(self):
        """
        사용자 정보가 없는 시스템에 사용자 정보를 동기화합니다.
        :param
            email : 사용자 email
        :return:
        성공할 경우 {
            "success": true,
            "synced_systems": ["system1", "system2"],
            "failed_systems": [],
            "skipped_systems": ["system3", "system4"]
        }
        오류 발생시 {
            "success": false,
            "error": "error message"
        }
        """
        param = request.json
        logger.debug(param)
        email = param["email"]
        
        # 1. MariaDB에서 사용자 정보 확인
        status, user_info = self.get_user_info_from_mariadb(email)
        if status != 0:
            return {"success": False, "error": "User not found in MariaDB"}, 404
            
        # 2. 각 시스템 상태 확인 및 동기화
        synced = []
        failed = []
        skipped = []
        
        try:
            # MinIO 확인 및 동기화
            mail_sha_code = make_sha_email(email)
            minio_client = Minio(minio_address, access_key=accesskey, secret_key=secretkey, secure=False)
            if mail_sha_code not in [bucket.name for bucket in minio_client.list_buckets()]:
                try:
                    minio_client.make_bucket(mail_sha_code)
                    synced.append("minio")
                except Exception as e:
                    logger.error(f"MinIO 동기화 실패: {str(e)}")
                    failed.append("minio")
            else:
                skipped.append("minio")
                
            # PGVector 확인 및 동기화
            try:
                vector_db = psycopg2.connect(
                    host=vector_postgres['address'],
                    dbname=vector_postgres['database'],
                    user=vector_postgres['id'],
                    password=vector_postgres['pwd'],
                    port=vector_postgres['port']
                )
                vt_cs = vector_db.cursor()
                vt_cs.execute(f"SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '{mail_sha_code}')")
                exists = vt_cs.fetchone()[0]
                
                if not exists:
                    create_table_sql = f'''CREATE TABLE public."{mail_sha_code}" (
                        "source" varchar(512) NULL,
                        "text" text NULL,
                        vector public.vector NULL,
                        id serial4 NOT NULL,
                        doc_id int4 NULL,
                        CONSTRAINT {mail_sha_code}_pk PRIMARY KEY (id)
                    );'''
                    vt_cs.execute(create_table_sql)
                    vector_db.commit()
                    synced.append("pgvector")
                else:
                    skipped.append("pgvector")
                vector_db.close()
            except Exception as e:
                logger.error(f"PGVector 동기화 실패: {str(e)}")
                failed.append("pgvector")
                
            # OpenSearch 확인 및 동기화
            try:
                client = get_opensearch_client()
                if client and not client.indices.exists(index=mail_sha_code.lower()):
                    success, msg = create_opensearch_index(mail_sha_code)
                    if success:
                        synced.append("opensearch")
                    else:
                        failed.append("opensearch")
                else:
                    skipped.append("opensearch")
            except Exception as e:
                logger.error(f"OpenSearch 동기화 실패: {str(e)}")
                failed.append("opensearch")
                
            # Qdrant 확인 및 동기화
            try:
                client = get_qdrant_client()
                if client:
                    collections = client.get_collections()
                    if mail_sha_code.lower() not in [col.name for col in collections.collections]:
                        success, msg = create_qdrant_collection(mail_sha_code)
                        if success:
                            synced.append("qdrant")
                        else:
                            failed.append("qdrant")
                    else:
                        skipped.append("qdrant")
            except Exception as e:
                logger.error(f"Qdrant 동기화 실패: {str(e)}")
                failed.append("qdrant")
                
            return {
                "success": True,
                "synced_systems": synced,
                "failed_systems": failed,
                "skipped_systems": skipped
            }
            
        except Exception as e:
            logger.error(f"동기화 중 오류 발생: {str(e)}")
            return {"success": False, "error": str(e)}, 500
    
    def get_user_info_from_mariadb(self, email):
        """MariaDB에서 사용자 정보를 가져옵니다."""
        try:
            mariadb_conn = pymysql.connect(
                user=opds_system_db["id"],
                password=opds_system_db["pwd"],
                database=opds_system_db["database"],
                host=opds_system_db["address"],
                port=opds_system_db["port"]
            )
            cs = mariadb_conn.cursor()
            sql = f'SELECT id, email, password, user_code FROM tb_user WHERE email="{email}"'
            cs.execute(sql)
            result = cs.fetchone()
            mariadb_conn.close()
            
            if result:
                return 0, {
                    "id": result[0],
                    "email": result[1],
                    "password": result[2],
                    "user_code": result[3]
                }
            return 1, None
        except Exception as e:
            logger.error(f"MariaDB 사용자 정보 조회 오류: {str(e)}")
            return -1, str(e)

@UserCode_NS.route('/get_usercode')
@UserCode_NS.response(400, 'BadRequest')
@UserCode_NS.response(500, 'Internal Server Error')
@UserCode_NS.response(503, 'Service Unavailable')
class UserCode(Resource):
    @UserCode_NS.expect(user_email_model)
    def post(self):
        """
        사용자의 암호화된 코드를 return
        :param
            email : 사용자 email
        :return:
        성공할 경우 {auth: True, "email": [email], "user_code": [user_code]}
        오류 발생시 {auth: False, "status":"User info is incorrect"}
        """
        param = request.json
        logger.debug(param)
        email = param["email"]
        status, user_code = get_usercode_by_username(email)
        if status == 0:
            json_rtn = {"auth": True,
                        "email": email,
                        "user_code": user_code}
            logger.debug(f"rtn : {json_rtn}")
            return build_actual_response(jsonify(json_rtn))
            # return jsonify(json_rtn)
        else:
            json_rtn = {"email": f"User email is incorrect {user_code}"}
            logger.debug(f"rtn : {json_rtn}")
            return {"email": f"User email is incorrect"}, 403


@Append_UserField_NS.route('/add_user')
@Append_UserField_NS.response(400, 'BadRequest')
@Append_UserField_NS.response(500, 'Internal Server Error')
@Append_UserField_NS.response(503, 'Service Unavailable')
class RegisterUser(Resource):
    @Append_UserField_NS.expect(add_user_model)
    def post(self):
        """
        새로운 사용자를 추가합니다. email, passwd를 사용합니다.
        :param
            email : 사용자 email
            new_passwd : 사용자 암호
        :return:
        성공할 경우 {auth: True, "status": "ok"}
        오류 발생시 {auth: False, "status":"Error message"}
        """
        logger.debug(f"register_user:{request}")
        param = request.json
        logger.debug(f"json param: {param}")
        if "email" not in param:
            json_rtn = {"auth": False,
                        "status": "email is empty"}
            return build_actual_response(jsonify(json_rtn)), 400
        if "new_passwd" not in param:
            json_rtn = {"auth": False,
                        "status": "password is empty"}
            return build_actual_response(jsonify(json_rtn)), 400

        email = param["email"]
        passwd = param["new_passwd"]

        logger.debug(f"add_user param: user_email : {email} passwd {passwd}")
        sts_code, msg = self.add_user(user_email=email, user_passwd=passwd)
        #사용자가 없어서 성공하면 0, ok
        #그외 : 사용자가 존재하거나, 암호가 틀린경우
        logger.debug(f"rtn sts_code : {sts_code} msg {msg}")
        if sts_code == -2: #DB Error
            json_rtn = {"auth": False,
                        "status": msg}
            logger.debug(f"rtn : {json_rtn}")
            return json_rtn, 500
        elif sts_code == -1: #Auth Fail
            json_rtn = {"auth": False,
                        "status": "Password is incorrect"}
            logger.debug(f"rtn : {json_rtn}")
            return json_rtn, 403
        elif sts_code == 1: #User exist
            json_rtn = {"auth": False,
                        "status": msg}
            logger.debug(f"rtn : {json_rtn}")
            return json_rtn, 403
        elif sts_code == 0:
            json_rtn = {"auth": True,
                        "status": "ok"}
            logger.debug(f"rtn : {json_rtn}")
            print(f"rtn : {json_rtn}")
            return build_actual_response(jsonify(json_rtn))


    def check_user_exists_all_systems(self, user_email):
        """모든 시스템에서 사용자 존재 여부를 확인합니다."""
        mail_sha_code = make_sha_email(user_email)
        exists = {
            'mariadb': False,
            'minio': False,
            'pgvector': False,
            'opensearch': False,
            'qdrant': False
        }
        
        # MariaDB 확인
        try:
            mariadb_conn = pymysql.connect(
                user=opds_system_db["id"],
                password=opds_system_db["pwd"],
                database=opds_system_db["database"],
                host=opds_system_db["address"],
                port=opds_system_db["port"]
            )
            cs = mariadb_conn.cursor()
            sql = f'SELECT COUNT(*) FROM tb_user WHERE email="{user_email}"'
            cs.execute(sql)
            count = cs.fetchone()[0]
            exists['mariadb'] = count > 0
            mariadb_conn.close()
        except Exception as e:
            logger.error(f"MariaDB 사용자 확인 오류: {str(e)}")
            return False, f"MariaDB Error: {str(e)}"

        # MinIO 확인
        try:
            minio_client = Minio(minio_address, access_key=accesskey, secret_key=secretkey, secure=False)
            exists['minio'] = mail_sha_code in [bucket.name for bucket in minio_client.list_buckets()]
        except Exception as e:
            logger.error(f"MinIO 사용자 확인 오류: {str(e)}")
            return False, f"MinIO Error: {str(e)}"

        # PGVector 확인
        try:
            vector_db = psycopg2.connect(
                host=vector_postgres['address'],
                dbname=vector_postgres['database'],
                user=vector_postgres['id'],
                password=vector_postgres['pwd'],
                port=vector_postgres['port']
            )
            vt_cs = vector_db.cursor()
            vt_cs.execute(f"SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '{mail_sha_code}')")
            exists['pgvector'] = vt_cs.fetchone()[0]
            vector_db.close()
        except Exception as e:
            logger.error(f"PGVector 사용자 확인 오류: {str(e)}")
            return False, f"PGVector Error: {str(e)}"

        # OpenSearch 확인
        try:
            client = get_opensearch_client()
            if client:
                exists['opensearch'] = client.indices.exists(index=mail_sha_code.lower())
        except Exception as e:
            logger.warning(f"OpenSearch 사용자 확인 오류 (무시됨): {str(e)}")

        # Qdrant 확인
        try:
            client = get_qdrant_client()
            if client:
                collections = client.get_collections()
                exists['qdrant'] = mail_sha_code.lower() in [col.name for col in collections.collections]
        except Exception as e:
            logger.warning(f"Qdrant 사용자 확인 오류 (무시됨): {str(e)}")

        # 결과 분석
        inconsistent = []
        for system, exists_flag in exists.items():
            if exists_flag:
                inconsistent.append(system)
        
        if inconsistent:
            return True, f"User exists in: {', '.join(inconsistent)}"
        return False, None

    def cleanup_user(self, user_email):
        """사용자 정보를 모든 시스템에서 제거합니다."""
        mail_sha_code = make_sha_email(user_email)
        
        # MariaDB 삭제
        try:
            mariadb_conn = pymysql.connect(
                user=opds_system_db["id"],
                password=opds_system_db["pwd"],
                database=opds_system_db["database"],
                host=opds_system_db["address"],
                port=opds_system_db["port"]
            )
            cs = mariadb_conn.cursor()
            sql = f"DELETE FROM tb_user WHERE email='{user_email}'"
            cs.execute(sql)
            mariadb_conn.commit()
            mariadb_conn.close()
        except Exception as e:
            logger.error(f"MariaDB 사용자 삭제 오류: {str(e)}")

        # MinIO 삭제
        try:
            minio_client = Minio(minio_address, access_key=accesskey, secret_key=secretkey, secure=False)
            if mail_sha_code in [bucket.name for bucket in minio_client.list_buckets()]:
                minio_client.remove_bucket(mail_sha_code)
        except Exception as e:
            logger.error(f"MinIO 사용자 삭제 오류: {str(e)}")

        # PGVector 삭제
        try:
            vector_db = psycopg2.connect(
                host=vector_postgres['address'],
                dbname=vector_postgres['database'],
                user=vector_postgres['id'],
                password=vector_postgres['pwd'],
                port=vector_postgres['port']
            )
            vt_cs = vector_db.cursor()
            vt_cs.execute(f'DROP TABLE IF EXISTS public."{mail_sha_code}"')
            vector_db.commit()
            vector_db.close()
        except Exception as e:
            logger.error(f"PGVector 사용자 삭제 오류: {str(e)}")

        # OpenSearch 삭제
        try:
            delete_opensearch_index(mail_sha_code)
        except Exception as e:
            logger.error(f"OpenSearch 사용자 삭제 오류: {str(e)}")

        # Qdrant 삭제
        try:
            delete_qdrant_collection(mail_sha_code)
        except Exception as e:
            logger.error(f"Qdrant 사용자 삭제 오류: {str(e)}")

    def add_user(self, user_email, user_passwd):
        """사용자를 추가합니다."""
        mail_sha_code = make_sha_email(user_email)
        systems_status = {
            'mariadb': {'exists': False, 'required': True},
            'minio': {'exists': False, 'required': True},
            'pgvector': {'exists': False, 'required': True},
            'opensearch': {'exists': False, 'required': True},
            'qdrant': {'exists': False, 'required':True}
        }
        
        # 1. 각 시스템별 사용자 존재 여부 확인
        try:
            # MariaDB 확인
            mariadb_conn = pymysql.connect(
                user=opds_system_db["id"],
                password=opds_system_db["pwd"],
                database=opds_system_db["database"],
                host=opds_system_db["address"],
                port=opds_system_db["port"]
            )
            cs = mariadb_conn.cursor()
            sql = f'SELECT COUNT(*) FROM tb_user WHERE email="{user_email}"'
            cs.execute(sql)
            count = cs.fetchone()[0]
            systems_status['mariadb']['exists'] = count > 0
            mariadb_conn.close()

            # MinIO 확인
            minio_client = Minio(minio_address, access_key=accesskey, secret_key=secretkey, secure=False)
            systems_status['minio']['exists'] = mail_sha_code in [bucket.name for bucket in minio_client.list_buckets()]

            # PGVector 확인
            vector_db = psycopg2.connect(
                host=vector_postgres['address'],
                dbname=vector_postgres['database'],
                user=vector_postgres['id'],
                password=vector_postgres['pwd'],
                port=vector_postgres['port']
            )
            vt_cs = vector_db.cursor()
            vt_cs.execute(f"SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '{mail_sha_code}')")
            systems_status['pgvector']['exists'] = vt_cs.fetchone()[0]
            vector_db.close()

            # OpenSearch 확인
            client = get_opensearch_client()
            if client:
                systems_status['opensearch']['exists'] = client.indices.exists(index=mail_sha_code.lower())

            # Qdrant 확인
            client = get_qdrant_client()
            if client:
                collections = client.get_collections()
                systems_status['qdrant']['exists'] = mail_sha_code.lower() in [col.name for col in collections.collections]

        except Exception as e:
            logger.error(f"시스템 상태 확인 중 오류 발생: {str(e)}")
            return -2, f"Error checking systems: {str(e)}"

        # # 2. 필수 시스템 중 하나라도 존재하면 사용자가 이미 있는 것으로 판단
        existing_systems = [sys for sys, status in systems_status.items() 
                          if status['exists'] and status['required']]
        # if existing_systems:
        #     return 1, f"User exists in: {', '.join(existing_systems)}"

        # 3. 각 시스템별로 사용자 정보 추가
        try:
            # MariaDB 추가
            if not systems_status['mariadb']['exists']:
                mariadb_conn = pymysql.connect(
                    user=opds_system_db["id"],
                    password=opds_system_db["pwd"],
                    database=opds_system_db["database"],
                    host=opds_system_db["address"],
                    port=opds_system_db["port"]
                )
                cs = mariadb_conn.cursor()
                h = hashlib.sha512()
                h.update(user_passwd.encode())
                encode_passwd = h.hexdigest()
                sql = "INSERT INTO tb_user (email, password, user_code) VALUES (%s, %s, %s)"
                cs.execute(sql, (user_email, encode_passwd, mail_sha_code))
                mariadb_conn.commit()
                mariadb_conn.close()
                logger.info(f"MariaDB에 사용자 추가됨: {user_email}")

            # MinIO 추가
            if not systems_status['minio']['exists']:
                minio_client = Minio(minio_address, access_key=accesskey, secret_key=secretkey, secure=False)
                minio_client.make_bucket(mail_sha_code)
                logger.info(f"MinIO에 버킷 생성됨: {mail_sha_code}")

            # PGVector 추가
            if not systems_status['pgvector']['exists']:
                vector_db = psycopg2.connect(
                    host=vector_postgres['address'],
                    dbname=vector_postgres['database'],
                    user=vector_postgres['id'],
                    password=vector_postgres['pwd'],
                    port=vector_postgres['port']
                )
                vt_cs = vector_db.cursor()
                
                # vector 확장 존재 여부 확인 및 등록
                vt_cs.execute("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector')")
                vector_exists = vt_cs.fetchone()[0]
                if not vector_exists:
                    logger.info("vector 확장 등록 시작")
                    vt_cs.execute("CREATE EXTENSION IF NOT EXISTS vector")
                    vector_db.commit()
                    logger.info("vector 확장 등록 완료")
                
                # 테이블 생성
                create_table_sql = f'''CREATE TABLE public."{mail_sha_code}" (
                    "source" varchar(512) NULL,
                    "text" text NULL,
                    vector vector NULL,
                    id serial4 NOT NULL,
                    doc_id int4 NULL,
                    CONSTRAINT {mail_sha_code}_pk PRIMARY KEY (id)
                );'''
                vt_cs.execute(create_table_sql)
                vector_db.commit()
                vector_db.close()
                logger.info(f"PGVector에 테이블 생성됨: {mail_sha_code}")

            # OpenSearch 추가 (선택사항)
            if not systems_status['opensearch']['exists']:
                success_os, msg_os = create_opensearch_index(mail_sha_code)
                if success_os:
                    logger.info(f"OpenSearch에 인덱스 생성됨: {mail_sha_code}")
                else:
                    logger.warning(f"OpenSearch 인덱스 생성 실패 (무시됨): {msg_os}")

            # Qdrant 추가 (선택사항)
            if not systems_status['qdrant']['exists']:
                success_qd, msg_qd = create_qdrant_collection(mail_sha_code)
                if success_qd:
                    logger.info(f"Qdrant에 컬렉션 생성됨: {mail_sha_code}")
                else:
                    logger.warning(f"Qdrant 컬렉션 생성 실패 (무시됨): {msg_qd}")

            return 0, "ok"  # 정상 추가됨

        except Exception as e:
            error_msg = str(e)
            logger.error(f"사용자 추가 중 오류 발생: {error_msg}")
            # 롤백 수행
            self.cleanup_user(user_email)
            return -2, f"Error: {error_msg}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=rest_config['port'], debug=False)