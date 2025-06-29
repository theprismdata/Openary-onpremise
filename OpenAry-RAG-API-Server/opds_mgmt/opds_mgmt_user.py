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

path = "log/preprocess.log"
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


    def add_user(self, user_email, user_passwd):
        auth_status, msg = check_exist_by_email(input_email=user_email, input_password=user_passwd)
        if auth_status == 1: # 해당 사용자 없음.
            minio_client = Minio(minio_address,
                                 access_key=accesskey,
                                 secret_key=secretkey, secure=False)

            # User information
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
                h.update(user_passwd.encode())
                encode_passwd = h.hexdigest()
                mail_sha_code = make_sha_email(user_email)

                sql = "INSERT INTO tb_user (email, password, user_code) VALUES ('{email}','{pwd}', '{user_code}')".format(
                    email=user_email, pwd=encode_passwd, user_code=mail_sha_code)
                cs.execute(sql)
                mariadb_conn.commit()
                mariadb_conn.close()

                if mail_sha_code not in minio_client.list_buckets():
                    minio_client.make_bucket(mail_sha_code)
            except Exception as e:
                logger.error(str(e))
                print('Mgmt DB Connection critical error')
                print(str(e))
                return -2, str(e)
            
            # VectorDB (PostgreSQL)
            try:
                vector_db = psycopg2.connect(host=vector_postgres['address'],
                                             dbname=vector_postgres['database'],
                                             user=vector_postgres['id'],
                                             password=vector_postgres['pwd'],
                                             port=vector_postgres['port'])
                create_table_sql = f'''CREATE TABLE public."{mail_sha_code}" (
                    "source" varchar(512) NULL,
                    "text" text NULL,
                    vector public.vector NULL,
                    id serial4 NOT NULL,
                    doc_id int4 NULL,
                    CONSTRAINT {mail_sha_code}_pk PRIMARY KEY (id)
                );
                '''
                vt_cs = vector_db.cursor()
                print(create_table_sql)
                vt_cs.execute(create_table_sql)
                vector_db.commit()
                vector_db.close()
            except Exception as e:
                logger.error(str(e))
                print('PGVector critical error')
                print(str(e))
                return -2, str(e)
            
            # OpenSearch 인덱스 생성 (선택사항)
            try:
                success, msg = create_opensearch_index(mail_sha_code)
                if success:
                    logger.info(f"OpenSearch 인덱스 생성 성공: {mail_sha_code}")
                else:
                    logger.warning(f"OpenSearch 인덱스 생성 실패하지만 계속 진행: {msg}")
            except Exception as e:
                logger.warning(f"OpenSearch 오류 발생하지만 계속 진행: {str(e)}")
            
            # Qdrant 컬렉션 생성 (선택사항)
            try:
                success, msg = create_qdrant_collection(mail_sha_code)
                if success:
                    logger.info(f"Qdrant 컬렉션 생성 성공: {mail_sha_code}")
                else:
                    logger.warning(f"Qdrant 컬렉션 생성 실패하지만 계속 진행: {msg}")
            except Exception as e:
                logger.warning(f"Qdrant 오류 발생하지만 계속 진행: {str(e)}")
                
            return 0, "ok" #정상 추가됨.
        elif auth_status == -1: #암호 오류 (사용자가 존재하는데 다시 모르고 가입하려는 경우)
            return -1, "Auth Fail"
        elif auth_status == 0: # 사용자 존재함.
            return 1, "User exist"
        elif auth_status == -2: # email DB 검증 오류
            return -2, f"DB Error {msg}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=rest_config['port'], debug=False)