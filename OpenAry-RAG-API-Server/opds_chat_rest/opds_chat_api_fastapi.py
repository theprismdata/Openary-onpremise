import hashlib
import json
import sys
import time
from logging.handlers import TimedRotatingFileHandler
import requests
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from langchain_community.utilities.tavily_search import TavilySearchAPIWrapper
from langchain_core.prompts import ChatPromptTemplate
from langchain.agents import tool
from langchain.callbacks import get_openai_callback
from langchain_core.output_parsers.openai_tools import JsonOutputToolsParser
from langchain_mongodb.chat_message_histories import MongoDBChatMessageHistory
from typing import Dict
import uvicorn
import os
import pymysql
import pandas as pd
import numpy as np
from minio import Minio
from pgvector.psycopg2 import register_vector
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette import status
from starlette.middleware.sessions import SessionMiddleware
from datetime import datetime, timedelta
import jwt
from starlette.requests import Request
import pika
from fastapi.openapi.utils import get_openapi
import yaml
from pytz import timezone
import pymongo
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_openai import ChatOpenAI
from typing import List
import re
from DBHandler import DatabaseConnectionManager
from DataModel import User, EmailInfo, DocFile, UserInfo, DropDocsInfo, EmailSession, ChatRQA
from typing import Optional
from langchain_openai import OpenAI
from fastapi.responses import StreamingResponse
import logging
from mecab import MeCab
from LLMIntentAnalyzer import LLMIntentAnalyzer
from question_classifier import QuestionClassifier
from LLMSelector import LLMSelector

print("build:2025-02-03-11:36")
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

ENV = os.getenv('ENVIRONMENT', 'development')
config_file = f'../config/svc-set.{"debug." if ENV == "development" else ""}yaml'

with open(config_file) as f:
    config = yaml.load(f, Loader=yaml.FullLoader)

rest_config = config['api_rest_config']
minio_info = config['minio']
minio_address = minio_info['address']
accesskey = minio_info['accesskey']
secretkey = minio_info['secretkey']
vector_postgres = config['database']['vector_db_postgres']
opds_system_db_info = config['database']['opds_system_db']

mongo_host = config['database']['mongodb']['mongo_host']
mongo_port = config['database']['mongodb']['mongo_port']
mongo_user = config['database']['mongodb']['mongo_user']
mongo_passwd = config['database']['mongodb']['mongo_passwd']
auth_source = config['database']['mongodb']['auth_source']
CHAT_HISTORY_SOURCE_DB = config['database']['mongodb']['chat_history']

SECRET_KEY = config['SECRET_KEY']
REFRESH_TOKEN_SECRET_KEY =  config['REFRESH_TOKEN_SECRET_KEY']

RABBITMQ_SVC_QUEUE = config['RABBITMQ_SVC_QUEUE']

OPDS_RREP_REQ_Q = RABBITMQ_SVC_QUEUE['PREPROCES_Q_NAME']
OPDS_RREP_ROUTE = RABBITMQ_SVC_QUEUE['PREPROCES_ROUTEKEY']

openai_api_key = config['langmodel']['API']['OpenAI']['apikey']
OpenAI_CHAT_MODEL = config['langmodel']['API']['OpenAI']['chat_model']

Ollama_model = config['langmodel']['LOCAL']['Ollama']['chat_model']
Ollama_address = config['langmodel']['LOCAL']['Ollama']['address']

TAVILY_API_KEY  = config['agent']['Tavily']
SERPER_KEY  = config['agent']['serperkey']

EMBEDDING_MODEL_ID = config['embeddingmodel']['sentensetransformer']['embedding_model']
MANAGEMENT_SERVICE = config['external_svc']['management_service']
MONGO_CONN_STRING = f"mongodb://{mongo_user}:{mongo_passwd}@{mongo_host}:{mongo_port}/?authSource={auth_source}&authMechanism=SCRAM-SHA-1"
MARIADB_DATABASE_URL = f'mysql+pymysql://{opds_system_db_info["id"]}:{opds_system_db_info["pwd"]}@{opds_system_db_info["address"]}:{opds_system_db_info["port"]}/{opds_system_db_info["database"]}'
PGVECTOR_DATABASE_URL = f'postgresql+psycopg2://{vector_postgres["id"]}:{vector_postgres["pwd"]}@{vector_postgres["address"]}:{vector_postgres["port"]}/{vector_postgres["database"]}'

if not os.path.exists(f'./embeddingmodel/{EMBEDDING_MODEL_ID}'):
    hugging_cmd = f'huggingface-cli download {EMBEDDING_MODEL_ID} --local-dir ./embeddingmodel/{EMBEDDING_MODEL_ID}'
    os.system(hugging_cmd)

embedding_model = HuggingFaceEmbeddings(
    model_name=f'./embeddingmodel/{EMBEDDING_MODEL_ID}/',
    model_kwargs={'device': 'cpu'}
)

mqtt_info = config['mqtt']
mqtt_id = mqtt_info['id']
mqtt_pwd = mqtt_info['pwd']
mqtt_address = mqtt_info['address']
mqtt_port = mqtt_info['port']
mqtt_virtualhost = mqtt_info['virtualhost']

UPLOAD_DIRECTORY = "uploads"
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

app = FastAPI(
    title="OpenAry Chat&FileUpload",
    description="채팅과 파일 업로드 제공",
    version="0.0.1",
    docs_url='/api/docs',
    redoc_url='/api/redoc'
)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
origins = ["*", "http://localhost:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,  # cookie 포함 여부를 설정한다. 기본은 False
    allow_methods=["*"],  # 허용할 method를 설정할 수 있으며, 기본값은 'GET'이다.
    allow_headers=["*"],  # 허용할 http header 목록을 설정할 수 있으며 Content-Type, Accept, Accept-Language, Content-Language은 항상 허용된다.
)
security = HTTPBearer()

"""
Generate secret key
import secrets
print(secrets.token_hex(32))
"""

def initialize_mecab():
    try:
        mecab = MeCab()
        logger.info("MeCab 형태소 분석기가 성공적으로 초기화되었습니다.")
        return mecab
    except Exception as e:
        logger.error(f"MeCab 초기화 오류: {str(e)}")
        logger.warn("MeCab 없이 계속 진행합니다.")
        return None

def analyze_korean_text(text, pos_filter=None, mecab_tagger=None):
    """
    한국어 텍스트를 형태소 분석하여 필터링된 단어 목록을 반환합니다.
    python-mecab-ko 패키지용으로 최적화됨

    Args:
        text (str): 분석할 텍스트
        pos_filter (list, optional): 추출할 품사 태그 목록. 기본값은 ['NNG', 'NNP', 'VV', 'VA']
        mecab_tagger: MeCab 태거 인스턴스

    Returns:
        str: 공백으로 구분된 형태소 문자열
    """
    if pos_filter is None:
        pos_filter = ['NNG', 'NNP', 'VV', 'VA']  # 기본: 일반명사, 고유명사, 동사, 형용사

    if mecab_tagger is None:
        import mecab
        mecab_tagger = mecab.MeCab()

    words = []

    # 형태소 분석 수행
    nodes = mecab_tagger.parse(text)

    for node in nodes:
        # 품사가 필터 목록에 있는 경우만 추출
        if node.pos in pos_filter:
            words.append(node.surface)

    return ' '.join(words)

mecab_tagger = initialize_mecab()


try:
    llm_selector = LLMSelector(Ollama_model, Ollama_address, logger, config)
    # llm_default = llm_selector.select_llm("default")  # 기본 LLM 설정
except Exception as e:
    print(f"Error initializing LLM selector: {e}")
    sys.exit(1)

mariadb_manager = DatabaseConnectionManager(logger,
    MARIADB_DATABASE_URL,
    pool_size=5,
    max_overflow=10,
    pool_timeout=30
)

pgvector_manager = DatabaseConnectionManager(logger,
    PGVECTOR_DATABASE_URL,
    pool_size=5,
    max_overflow=10,
    pool_timeout=30
)


def get_usercode_from_email(user_email):
    try:
        with mariadb_manager.get_session() as db:
            user_obj = db.query(User).filter(User.email == user_email).first()
            return user_obj.user_code if user_obj else None
    except Exception as e:
        logger.error(f"Error getting user code: {str(e)}")
        return None

def check_user_exist(user_email: str):
    try:
        with mariadb_manager.get_session() as db:
            user_obj = db.query(User).filter(User.email == user_email).first()
            return user_obj is not None
    except Exception as e:
        logger.error(f"Error checking user existence: {str(e)}")
        return False

def sentent_embedding(sentence):
    embedded_content = embedding_model.embed_query(sentence)
    return embedded_content

def get_llm_message_cache(messages, model="gpt-4o", temperature=0, max_tokens=1000):
    with get_openai_callback() as callback:
        OpenAI_client = OpenAI.OpenAI(api_key=openai_api_key)
        response = OpenAI_client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        logger.debug("Total Tokens:", callback.total_tokens)
        return response.choices[0].message.content

def get_relevant_vector_doc_top3(pgvector_conn, user_code, embedding_vector):
    cur = pgvector_conn.cursor()
    cur.execute(
        f"""SELECT source, text, 1 - (vector <=> %s) AS cosine_similarity 
               FROM {user_code} 
               ORDER BY cosine_similarity DESC LIMIT 3""",
        (embedding_vector,))
    top3_docs = cur.fetchall()
    top_related_doc = []
    for top_doc in top3_docs:
        if top_doc[2] > 0.4:
            top_related_doc.append((top_doc[0], top_doc[1]))
    return top_related_doc

def get_openapi_schema():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "Bearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme."
        }
    }
    for path in openapi_schema["paths"].values():
        for operation in path.values():
            operation["security"] = [{"Bearer": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = get_openapi_schema

@tool
def serper_search(query: str) -> str:
    """Search for information using Serper API."""
    try:
        headers = {
            'X-API-KEY': SERPER_KEY,
            'Content-Type': 'application/json'
        }
        payload = json.dumps({
            "q": query,
            "num": 3
        })
        response = requests.post('https://google.serper.dev/search', headers=headers, data=payload)
        if response.status_code == 200:
            results = response.json()
            formatted_results = []
            for item in results.get('organic', []):
                formatted_results.append({
                    "title": item.get('title', ''),
                    "content": item.get('snippet', ''),
                    "url": item.get('link', '')
                })
            return json.dumps(formatted_results, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Serper search error: {str(e)}")
        return "[]"


@tool
def web_search(query: str) -> str:
    """Search for real-time information about a given query."""
    try:
        # logger.debug(f"Tavily query {query}")
        search = TavilySearchAPIWrapper(tavily_api_key=TAVILY_API_KEY)
        results = search.results(query, max_results=3)
        return json.dumps(results, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Tavily search error: {str(e)}")
        return "[]"

tools = [web_search, serper_search]

# OpenAI 모델 설정
agent_llm = ChatOpenAI(
    model=OpenAI_CHAT_MODEL,
    temperature=0,
    openai_api_key=openai_api_key,
)

try:
    llm_with_tools = agent_llm.bind_tools(
        tools,
        tool_choice={"type": "function", "function": {"name": "web_search"}}
    )
    searchchain_tools = llm_with_tools | JsonOutputToolsParser(tools=tools)
except Exception as e:
    logger.error(f"Error setting up search chain: {str(e)}")

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    JWT 토큰을 검증하는 함수
    """
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    ACCESS JWT 토큰을 생성합니다.
    Args:
        data (dict): 토큰에 인코딩할 데이터
        expires_delta (Optional[timedelta]): 토큰 만료 시간

    Returns:
        str: 생성된 JWT 토큰
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    refresh 토큰을 생성합니다.
    Args:
        data (dict): 토큰에 인코딩할 데이터
        expires_delta (timedelta | None, optional):토큰 만료 시간
    Returns:
        str: 생성된 JWT 토큰
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, REFRESH_TOKEN_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verity_jwt_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_system_db():
    with mariadb_manager.get_session() as session:
        yield session

def get_pgvector_db():
    with pgvector_manager.get_session() as session:
        yield session

class FileResponse(BaseModel):
    """
    개별 파일 응답 모델
    """
    filename: str
    file_size: int
    content_type: str

    class Config:
        schema_extra = {
            "example": {
                "filename": "test.txt",
                "file_size": 1024,
                "content_type": "text/plain"
            }
        }


class UploadResponse(BaseModel):
    """
    전체 업로드 응답 모델
    """
    email: str = "guest@openary.io"
    files: List[FileResponse]
    total_files: int
    total_size: int

    class Config:
        schema_extra = {
            "example": {
                "email": "test@example.com",
                "files": [
                    {
                        "filename": "test1.txt",
                        "file_size": 1024,
                        "content_type": "text/plain"
                    },
                    {
                        "filename": "test2.jpg",
                        "file_size": 2048,
                        "content_type": "image/jpeg"
                    }
                ],
                "total_files": 2,
                "total_size": 3072
            }
        }


@app.post("/chatapi/login",
        summary="로그인 및 JWT 토큰 발급",
        description="이메일과 비밀번호로 로그인하여 JWT 토큰을 발급받습니다.",
        response_description="JWT 액세스 토큰")
def login_act(signin_data: UserInfo):
    try:
        with mariadb_manager.get_session() as db:
            user = db.query(User).filter(User.email == signin_data.email).first()
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"User not found with email: {signin_data.email}"
                )

            input_password = signin_data.password
            h = hashlib.sha512()
            h.update(input_password.encode())
            desc_passwd = h.hexdigest()

            if desc_passwd == user.password:
                token = create_access_token(data={"sub": user.email})
                refresh_token = create_refresh_token(data={"id": user.id})
                response = JSONResponse({
                    "token": token,
                    "refresh": refresh_token,
                    "email": user.email
                }, status_code=200)
                response.set_cookie(key="refresh-Token", value=refresh_token)
                return response
            else:
                raise HTTPException(status_code=403, detail="Invalid credentials")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


async def check_cookie(request: Request):
    cookie = request.cookies
    if not cookie:
        return None
    if cookie.get('refresh-Token'):
        return cookie.get('refresh-Token')

def get_user_by_id(db:Session, id:int) -> User | None:
    """
    Get user by id
    Args:
        db (Session): database session
        id (int): user id
    Returns:
        User | None: user object if user exists, None otherwise (if user does not exist in the database, return None)
    """
    user = db.query(User).filter(User.id == id).first()
    if not user:
        return None
    return user


async def decode_token(token: str, key: str | None = None, type: str = 'access') -> str | None:
    """
    Decode a JWT token

    Args:
        token (str): JWT token
        key (str | None, optional): key to extract from the token. Defaults to None.
        type (str, optional): type of token [refresh or access]
    Returns:
        str | None: extracted data from the token or None if token is invalid.
    """
    try:
        if type == 'refresh':
            payload = jwt.decode(token, REFRESH_TOKEN_SECRET_KEY, algorithms=[ALGORITHM])
        else:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if key:
            return payload.get(key)
        return payload.get('sub')
    except Exception as e:
        print(e)
        return None

@app.post("/chatapi/getdocs")
async def getdocs(emailInfo: EmailInfo, token_data: dict = Depends(verify_token)):
    try:
        user_code = get_usercode_from_email(emailInfo.email)
        filesummary = []

        # 커넥션 풀 사용
        with mariadb_manager.get_session() as db:
            docfiles = db.query(DocFile).filter(DocFile.userid == user_code).all()

            for docfile in docfiles:
                filesummary.append({
                    'filename': docfile.filename,
                    'summary': docfile.summary,
                    'ext_page_rate': docfile.extract_page_rate,
                    'embedding_rate': docfile.embedding_rate
                })

        return JSONResponse({
            "fileinfo": filesummary,
            "email": emailInfo.email,
            "usercode": user_code
        }, status_code=200)

    except Exception as e:
        logger.error(f"Error in getdocs: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving documents: {str(e)}"
        )


@app.post("/chatapi/dropdocs")
async def dropdocs(dropdocsInfo: DropDocsInfo, token_data: dict = Depends(verify_token)):
    try:
        user_code = get_usercode_from_email(dropdocsInfo.email)
        delfile_cnt = 0

        # MariaDB 삭제 작업
        with mariadb_manager.get_session() as db:
            for docfile in dropdocsInfo.files:
                result = db.execute(
                    text("""DELETE FROM tb_llm_doc 
                           WHERE userid=:user_code AND filename=:filename"""),
                    {"user_code": user_code, "filename": docfile}
                )
                delfile_cnt += result.rowcount

        # PGVector 삭제 작업
        with pgvector_manager.get_session() as db:
            for docfile in dropdocsInfo.files:
                db.execute(
                    f"""DELETE FROM {user_code} 
                       WHERE source=:source""",
                    {"source": docfile}
                )

        return JSONResponse({
            "delcount": delfile_cnt,
            "usercode": user_code,
            "email": dropdocsInfo.email
        }, status_code=200)

    except Exception as e:
        logger.error(f"Error in dropdocs: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error deleting documents: {str(e)}"
        )

@app.post("/chatapi/refresh")
async def refresh_token(refresh_token: str = Depends(check_cookie), db: Session = Depends(get_system_db)):
    """
    Create a refresh token route
    """
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")
    decoded_token = await decode_token(refresh_token, 'id', type='refresh')
    if not decoded_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = get_user_by_id(db, decoded_token)
    if not user:
        raise HTTPException(status_code=401, detail="User does not exist")
    access_token = create_access_token(data={"sub": user.email})
    return JSONResponse({"token": access_token, "email": user.email}, status_code=200)

@app.post("/chatapi/dropasessionhistory/",
          summary="선택한 채팅 세션의 대화 기록 삭제",
          description="접속한 사용자 이메일, 채팅 세션 ID를 받습니다.",
          response_description="사용자 이메일과 삭제한 대화 건수")
def dropasessionhistory(sesshist: EmailSession, token_data: dict = Depends(verify_token)):
    """
    개별 히스토리 삭제
    email : 접속한 사용자 email <br>
    sessionid : 대화 History id <br>
    """
    user_code = get_usercode_from_email(sesshist.email)
    mongo_client = pymongo.MongoClient(MONGO_CONN_STRING)
    llm_chat_history_db = mongo_client[CHAT_HISTORY_SOURCE_DB]

    user_code_coll = llm_chat_history_db['user_code']
    rtn = user_code_coll.delete_many({"user_code": user_code, "SessionId": sesshist.session})
    user_code_history = llm_chat_history_db[user_code]
    rtn = user_code_history.delete_many({"SessionId": sesshist.session})
    if rtn.raw_result['ok'] == 1.0:
        drop_cnt = rtn.raw_result['n']
        json_rtn = {"user_code": user_code,"user_email": sesshist.email, 'status': 'ok', 'drop_cnt' : drop_cnt}
    else:
        json_rtn = {"user_code": user_code, "user_email": sesshist.email, 'status': 'fail'}
    return json_rtn


@app.post("/chatapi/getasessionhistory/",
          summary="선택한 채팅 세션의 대화 기록",
          description="접속한 사용자 이메일, 채팅 세션 ID를 받습니다.",
          response_description="사용자 이메일과 대화 목록"
          )
def getasessionhistory(sesshist: EmailSession, token_data: dict = Depends(verify_token)):
    """
    채팅 세션 하나의 대화 기록 리턴 <br>
    email : 접속한 사용자 email <br>
    """
    user_code = get_usercode_from_email(sesshist.email)
    #사용자가 여러개의 셔선을 가질 수 있음.
    #하나의 세션에 많은 대화가 기록되어 있음.
    chain_with_history = MongoDBChatMessageHistory(
        session_id=sesshist.session,
        connection_string=MONGO_CONN_STRING,
        database_name=CHAT_HISTORY_SOURCE_DB,
        collection_name=user_code,
    )
    # 과거 대화 로드.
    chat_history = []
    session_messages = chain_with_history.messages
    for idx, session_message in enumerate(session_messages):
        itemn = idx+1
        if itemn % 4 == 1:
            question = session_message.content
        elif itemn % 4 == 2:
            ai_response = session_message.content
        elif itemn % 4 == 3:
            source_response = session_message.content
            try:
                source_dict = json.loads(source_response)
                if 'sourcelist' in source_dict:
                    sourcelist = json.loads(source_response)['sourcelist']
            except Exception as e:
                logger.debug(f"history : {source_response}")
                sourcelist= []

        elif itemn % 4 == 0:
            srch_response = session_message.content
            searchlist = []
            try:
                srch_contents = json.loads(srch_response)
                if 'searchlist' in srch_contents:
                    for srch_content in srch_contents['searchlist']:
                        searchlist.append(srch_content)
            except Exception as e:
                logger.debug(f"history : {srch_response}")


            chat_history.append({'question': question,
                                 'answer': ai_response,
                                 'sourcelist': sourcelist,
                                 'searchlist': searchlist})

    json_rtn = {"user_code": user_code,
                "user_email": sesshist.email,
                "history": chat_history}
    return json_rtn

@app.post("/chatapi/getsessionlist/",
          summary="전체 대화 기록",
          description="접속한 사용자 이메일로 히스토리 ID와 대화 제목을 받습니다.",
          response_description="사용자 코드,  히스토리 ID, 대화 제목"
          )
def getsessionlist(email_info: EmailInfo, token_data: dict = Depends(verify_token)):
    """
    채팅 히스토리 <br>
    email : 접속한 사용자 email <br>
    """
    user_code = get_usercode_from_email(email_info.email)
    mongo_client = pymongo.MongoClient(MONGO_CONN_STRING)
    llm_chat_history_db = mongo_client[CHAT_HISTORY_SOURCE_DB]
    user_code_coll = llm_chat_history_db['user_code']
    session_list = []
    for session in user_code_coll.find({"user_code": user_code}):
        session_list.append({session['SessionId']: session['chat']})
    json_rtn = {"user_code": user_code,"user_email": email_info.email,  "session_list": session_list}
    return json_rtn


from transformers import AutoTokenizer
from typing import List, Tuple

class ChatHistoryManager:
    def __init__(self, mongo_connection_string: str, database_name: str, max_history: int = 3):
        """
        Chat History 관리자 초기화
        Args:
            mongo_connection_string: MongoDB 연결 문자열
            database_name: 데이터베이스 이름
            max_history: 유지할 최대 대화 기록 수 (기본값: 3)
        """
        self.mongo_connection_string = mongo_connection_string
        self.database_name = database_name
        self.max_history = max_history

    def get_message_history(self, session_id: int, collection_name: str) -> MongoDBChatMessageHistory:
        """MongoDB 기반 메시지 히스토리 객체 생성"""
        return MongoDBChatMessageHistory(
            session_id=session_id,
            connection_string=self.mongo_connection_string,
            database_name=self.database_name,
            collection_name=collection_name
        )

    def get_recent_messages(self, history: MongoDBChatMessageHistory) -> List[Dict]:
        """
        최근 N개의 대화 내용을 가져와서 요약된 형태로 반환
        """
        messages = history.messages
        recent_messages = []
        message_count = 0

        # messages를 4개씩 그룹화하여 처리 (question, answer, source, search)
        for i in range(0, len(messages), 4):
            if message_count >= self.max_history:
                break

            group = messages[i:i + 4]
            if len(group) >= 2:  # 최소한 질문과 답변이 있는 경우만 처리
                summary = {
                    "role": "assistant",
                    "content": f"이전 질문: {group[0].content}\n답변 요약: {self._summarize_response(group[1].content)}"
                }
                recent_messages.append(summary)
                message_count += 1

        return recent_messages

    def _summarize_response(self, response: str, max_length: int = 100) -> str:
        """
        긴 응답을 요약하는 헬퍼 함수
        현재는 단순 절삭 방식이지만, 필요에 따라 더 정교한 요약 로직으로 교체 가능
        """
        if len(response) <= max_length:
            return response
        return response[:max_length] + "..."

    def format_history_for_prompt(self, messages: List[Dict]) -> str:
        """
        History 메시지들을 프롬프트에 포함시킬 형태로 포맷팅
        """
        formatted_history = []
        for msg in messages:
            formatted_history.append(msg["content"])
        return "\n".join(formatted_history)

    def add_interaction(self,
                        history: MongoDBChatMessageHistory,
                        question: str,
                        answer: str,
                        sources: List[str],
                        search_results: List[Dict] = None):
        """새로운 대화 내용을 추가"""
        history.add_user_message(question)
        history.add_ai_message(answer)
        history.add_ai_message(json.dumps({"sourcelist": sources}))
        history.add_ai_message(json.dumps({"searchlist": search_results or []}))

history_manager = ChatHistoryManager(
    mongo_connection_string=MONGO_CONN_STRING,
    database_name=CHAT_HISTORY_SOURCE_DB
)

def get_unknown_words_from_text(text, mecab_tagger=None):
    """
    주어진 텍스트에서 MeCab이 인식하지 못하는 단어를 추출합니다.

    Args:
        text (str): 분석할 텍스트
        mecab_tagger: MeCab 태거 인스턴스

    Returns:
        list: 인식되지 않은 단어 목록
    """
    unknown_words = []
    nodes = mecab_tagger.parse(text)

    for node in nodes:
        # 결과 구조에 따라 필드 접근
        word = node.surface
        pos = node.pos

        # python-mecab-ko에서 미등록어 판단 기준
        # 1. 'SL' 태그가 붙은 단어 (외국어로 분류된 경우)
        # 2. 'UNKNOWN' 태그
        if (pos == 'SL' and len(word) > 1) or pos == 'UNKNOWN':
            unknown_words.append(word)

    return unknown_words


class HybridResponseStreamer:
    """
    RAG와 Agent를 순차적으로 실행하여 하이브리드 응답을 생성하는 스트리머 클래스
    """
    def __init__(self, rqa, token_data):
        """
        Args:
            rqa: 사용자 질문 객체
            token_data: 인증 토큰 데이터
        """
        self.rqa = rqa
        self.token_data = token_data
        self.mongo_client = None
        self.session_id = None
        self.user_code = None
        self.seen_sources = []
        self.related_docs = []
        self.search_results = []
        self.start_time = time.time()
        self.rag_response = ""
        self.agent_response = ""
        self.hybrid_response = ""
        self.rag_sources = []
        self.agent_search_results = []
        self.rag_confidence = 0.0
        self.agent_confidence = 0.0
        self.intent_analyzer = LLMIntentAnalyzer(logger, llm_selector)
        self.question_classifier = QuestionClassifier(llm_selector, logger)

    def initialize(self):
        """사용자 검증 및 초기화"""
        if not check_user_exist(self.rqa.email):
            return False

        self.user_code = get_usercode_from_email(self.rqa.email)
        return True

    def setup_mongodb(self):
        """MongoDB 연결 및 세션 ID 설정"""
        self.mongo_client = pymongo.MongoClient(MONGO_CONN_STRING)
        llm_chat_history_db = self.mongo_client[CHAT_HISTORY_SOURCE_DB]
        user_sessions_coll = llm_chat_history_db['user_code']

        # 세션 ID 결정
        session_lst = user_sessions_coll.find_one({"SessionId": self.rqa.session_id})
        self.session_id = (int(datetime.now().timestamp()) if session_lst is None or self.rqa.isnewsession
                           else self.rqa.session_id)

        return llm_chat_history_db, user_sessions_coll

    def get_user_files(self):
        """사용자 파일 목록 가져오기"""
        files = []

        try:
            with mariadb_manager.get_session() as db:
                query = text("""
                    SELECT id, filename, filesize, status, uploaded, summary, extract_page_rate, embedding_rate
                    FROM tb_llm_doc 
                    WHERE userid = :user_code
                    ORDER BY uploaded DESC
                """)

                result = db.execute(query, {"user_code": self.user_code})

                for row in result:
                    uploaded_date = row[4]
                    if isinstance(uploaded_date, datetime):
                        formatted_date = uploaded_date.strftime("%Y-%m-%d %H:%M")
                    else:
                        formatted_date = str(uploaded_date)

                    files.append({
                        "id": row[0],
                        "filename": row[1],
                        "filesize": row[2],
                        "status": row[3],
                        "uploaded": uploaded_date,
                        "uploaded_formatted": formatted_date,
                        "summary": row[5],
                        "extract_page_rate": row[6],
                        "embedding_rate": row[7]
                    })

        except Exception as e:
            logger.error(f"파일 목록 검색 중 오류: {str(e)}")

        return files

    def _is_technical_content(self, question):
        """
        기술적 내용(코드, SQL 등)인지 확인
        LLMIntentAnalyzer를 사용하여 분석
        """
        try:
            # 이미 intent_analyzer가 초기화되어 있으므로 바로 사용
            return self.intent_analyzer.is_technical_content_llm(question)
        except Exception as e:
            self.logger.error(f"기술 내용 감지 오류: {str(e)}")
            return False

    def get_technical_prompt_template(self, llm_type):
        """기술적 내용에 특화된 프롬프트 템플릿 반환"""
        if llm_type == "Claude":
            return ChatPromptTemplate.from_messages([
                ("system", """공공기관과 IT기업을 위한 전문 기술 어시스턴트로서, 프로그래밍 코드, SQL, Docker 등의 기술적 내용에 
                대응합니다. 코드나 기술적인 내용은 절대 요약하지 말고 전체 내용을 그대로 유지하세요. 
                코드 블록은 항상 완전한 형태로 제공하고, 주석을 포함한 모든 세부 사항을 보존해야 합니다."""),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "{input}"),
                ("human", "내부 문서 정보: {context}"),
                ("human", "외부 검색 결과: {search_results}")
            ])
        elif llm_type == "Gemma":
            return ChatPromptTemplate.from_messages([
                ("system", """전문 기술 어시스턴트입니다. 프로그래밍 코드, SQL, Docker 등의 기술적 내용은 
                요약하지 않고 완전한 형태로 제공합니다."""),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "질문: {input}\n\n내부 문서 정보: {context}\n\n외부 검색 결과: {search_results}")
            ])
        else:  # OpenAI, Ollama 등
            return ChatPromptTemplate.from_messages([
                ("system", """전문 기술 어시스턴트입니다. 프로그래밍 코드, SQL, Docker 등의 기술적 내용은 
                요약하지 않고 완전한 형태로 제공합니다."""),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "{input}"),
                ("human", "내부 문서 정보: {context}"),
                ("human", "외부 검색 결과: {search_results}")
            ])

    def perform_vector_search(self):
        """벡터 검색 수행 (RAG)"""
        logger.debug("내부 벡터 검색(RAG) 시작")

        with pgvector_manager.get_session() as db_pg:
            register_vector(db_pg.bind.raw_connection())

            # 미등록 단어 식별
            unknown_words = get_unknown_words_from_text(self.rqa.question, mecab_tagger)
            logger.debug(f"미등록 단어: {unknown_words}")

            # 기본 형태소 분석 및 임베딩
            processed_query = analyze_korean_text(self.rqa.question)
            logger.debug(f"원본 질문: {self.rqa.question}")
            logger.debug(f"형태소 분석 결과: {processed_query}")

            # 기본 임베딩 생성
            base_embedding = embedding_model.embed_query(processed_query)
            base_vector = np.array(base_embedding)

            # 명사 추출 및 임베딩
            key_nouns = analyze_korean_text(self.rqa.question, pos_filter=['NNG', 'NNP'])
            if key_nouns:
                logger.debug(f"핵심 명사: {key_nouns}")
                noun_embedding = embedding_model.embed_query(key_nouns)
                noun_vector = np.array(noun_embedding)
            else:
                noun_vector = base_vector

            # 미등록 단어 임베딩
            if unknown_words:
                unknown_text = " ".join(unknown_words)
                logger.debug(f"미등록 단어 텍스트: {unknown_text}")
                unknown_embedding = embedding_model.embed_query(unknown_text)
                unknown_vector = np.array(unknown_embedding)
            else:
                unknown_vector = base_vector

            # 가중치 결합 벡터 생성
            combined_vector = 0.5 * base_vector + 0.3 * noun_vector + 0.2 * unknown_vector
            combined_vector = combined_vector / np.linalg.norm(combined_vector)

            # 디버깅을 위한 로깅
            logger.debug(f"벡터 결합 완료: 기본(0.5) + 명사(0.3) + 미등록 단어(0.2)")

            # 벡터 검색 실행
            result = db_pg.execute(
                text(f"""SELECT source, text, 1 - (vector <=> :vector) AS cosine_similarity 
                       FROM {self.user_code} 
                       ORDER BY cosine_similarity DESC LIMIT 5"""),
                {"vector": combined_vector}
            )

            # 검색 결과 처리
            top_docs = result.fetchall()
            self.rag_sources = []
            self.related_docs = []

            for doc in top_docs:
                sim_rate = doc[2]
                if sim_rate > 0.45:  # 유사도 임계값
                    if doc[0] not in self.rag_sources:
                        self.rag_sources.append(doc[0])
                        self.related_docs.append(doc[1])
                        logger.debug(f"관련 문서: {doc[0]}, 유사도: {sim_rate:.4f}")

            # RAG 신뢰도 계산 (관련 문서 수와 유사도를 기반으로)
            if len(self.related_docs) > 0:
                avg_sim_rate = sum(doc[2] for doc in top_docs[:len(self.related_docs)]) / len(self.related_docs)
                self.rag_confidence = min(0.95, avg_sim_rate * 0.8 + 0.3)  # 유사도 기반 신뢰도 계산
            else:
                self.rag_confidence = 0.1  # 관련 문서가 없으면 낮은 신뢰도

        logger.debug(f"RAG 검색 완료: 소스 {len(self.rag_sources)}개, 신뢰도 {self.rag_confidence:.2f}")

    def perform_external_search(self):
        """외부 검색 수행 (Agent)"""
        logger.debug("외부 검색(Agent) 시작")

        try:
            self.agent_search_results = process_tool_calls(self.rqa.question)
            logger.debug(f"외부 검색 결과: {len(self.agent_search_results)} 항목")

            # Agent 신뢰도 계산 (검색 결과 수와 관련성을 기반으로)
            if len(self.agent_search_results) > 0:
                # 검색 결과 개수와 질문의 시간적 특성에 따른 신뢰도 조정
                temporal_keywords = ["오늘", "최근", "지금", "현재", "이번"]
                has_temporal = any(kw in self.rqa.question for kw in temporal_keywords)

                if has_temporal:
                    self.agent_confidence = min(0.95, 0.7 + len(self.agent_search_results) * 0.05)
                else:
                    self.agent_confidence = min(0.85, 0.5 + len(self.agent_search_results) * 0.05)
            else:
                self.agent_confidence = 0.2  # 검색 결과가 없으면 낮은 신뢰도

            logger.debug(f"Agent 검색 완료: 결과 {len(self.agent_search_results)}개, 신뢰도 {self.agent_confidence:.2f}")
            return self.agent_search_results
        except Exception as e:
            logger.error(f"외부 검색 중 오류: {str(e)}")
            self.agent_confidence = 0.0
            return []

    def save_to_mongodb(self, user_sessions_coll, full_response, method="hybrid"):
        """MongoDB에 세션 및 대화 저장"""
        # 세션 저장
        session_doc = {
            'SessionId': self.session_id,
            'user_code': self.user_code,
            'chat': self.rqa.question
        }

        if self.rqa.isnewsession:
            user_sessions_coll.insert_one(session_doc)
        else:
            user_sessions_coll.update_one(
                {'SessionId': self.session_id, 'user_code': self.user_code},
                {'$set': {"chat": self.rqa.question}}
            )

        mongochat_history = MongoDBChatMessageHistory(
            session_id=self.session_id,
            connection_string=MONGO_CONN_STRING,
            database_name=CHAT_HISTORY_SOURCE_DB,
            collection_name=self.user_code,
        )

        # 하이브리드 모드에서는 RAG 소스와 Agent 검색 결과를 모두 저장
        history_manager.add_interaction(
            history=mongochat_history,
            question=self.rqa.question,
            answer=full_response,
            sources=self.rag_sources,
            search_results=self.agent_search_results,
        )

    def get_rag_prompt_template(self, llm_type):
        """RAG용 프롬프트 템플릿 반환"""
        if llm_type == "Claude":
            return ChatPromptTemplate.from_messages([
                ("system", "공공기관과 IT기업을 위한 전문 리서치 어시스턴트로서, 제공된 문서와 데이터를 기반으로 객관적이고 구조화된 보고서 형식의 답변을 작성합니다."),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "질문: {input}"),
                ("human", "연관 정보: {context}")
            ])
        elif llm_type == "Gemma":
            return ChatPromptTemplate.from_messages([
                ("system", "다음 질문에 대해 제공된 정보를 바탕으로 답변해주세요."),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "질문: {input}\n\n참고 정보: {context}")
            ])
        else:  # OpenAI, Ollama 등
            return ChatPromptTemplate.from_messages([
                ("system", "전문 리서치 어시스턴트입니다."),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "{input}"),
                ("human", "연관 정보: {context}")
            ])

    def get_agent_prompt_template(self, llm_type):
        """Agent(외부 검색)용 프롬프트 템플릿 반환"""
        if llm_type == "Claude":
            return ChatPromptTemplate.from_messages([
                ("system", "공공기관과 IT기업을 위한 전문 리서치 어시스턴트로서, 최신 정보와 데이터를 검색하여 객관적이고 정확한 답변을 제공합니다."),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "질문: {input}"),
                ("human", "검색 결과: {search_results}")
            ])
        elif llm_type == "Gemma":
            return ChatPromptTemplate.from_messages([
                ("system", "최신 정보를 검색하여 답변하는 리서치 어시스턴트입니다."),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "질문: {input}\n\n검색 정보: {search_results}")
            ])
        else:
            return ChatPromptTemplate.from_messages([
                ("system", "최신 정보를 검색하여 답변하는 리서치 어시스턴트입니다."),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "{input}"),
                ("human", "검색 결과: {search_results}")
            ])

    def get_hybrid_prompt_template(self, llm_type):
        """하이브리드(RAG + Agent) 프롬프트 템플릿 반환"""
        if llm_type == "Claude":
            return ChatPromptTemplate.from_messages([
                ("system", """공공기관과 IT기업을 위한 전문 리서치 어시스턴트로서, 내부 문서와 최신 외부 검색 결과를 함께 활용하여 
                종합적이고 정확한 답변을 제공합니다. 내부 문서 정보와 외부 검색 정보를 모두 참고하되, 정보의 출처를 명확히 구분하여 제시합니다."""),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "질문: {input}"),
                ("human", "내부 문서 정보: {context}"),
                ("human", "외부 검색 결과: {search_results}")
            ])
        elif llm_type == "Gemma":
            return ChatPromptTemplate.from_messages([
                ("system", """내부 문서 정보와 외부 검색 결과를 모두 활용하여 종합적인 답변을 제공하는 리서치 어시스턴트입니다. 
                두 정보 소스를 적절히 조합하여 완성도 높은 답변을 작성하세요."""),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "질문: {input}\n\n내부 문서 정보: {context}\n\n외부 검색 결과: {search_results}")
            ])
        else:
            return ChatPromptTemplate.from_messages([
                ("system", """내부 문서와 외부 검색 결과를 모두 활용하여 종합적인 답변을 제공하는 리서치 어시스턴트입니다. 
                두 정보 소스를 적절히 조합하고, 필요시 정보의 출처를 명시해 주세요."""),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "{input}"),
                ("human", "내부 문서 정보: {context}"),
                ("human", "외부 검색 결과: {search_results}")
            ])

    def _format_search_results(self, search_results):
        """검색 결과를 프롬프트용으로 포맷팅"""
        if not search_results:
            return "검색 결과가 없습니다."

        formatted = "다음은 질문과 관련된 검색 결과입니다:\n\n"

        for idx, result in enumerate(search_results[:5], 1):  # 최대 5개까지만 포함
            formatted += f"[검색 결과 {idx}]\n"

            if "title" in result:
                formatted += f"제목: {result['title']}\n"

            if "content" in result:
                content = result["content"]
                # 너무 길면 잘라내기
                if len(content) > 300:
                    content = content[:300] + "..."
                formatted += f"내용: {content}\n"

            if "url" in result:
                formatted += f"출처: {result['url']}\n"

            formatted += "\n"

        return formatted

    def generate_rag_response(self, selected_llm, llm_type, conversation_history):
        """RAG 기반 응답 생성"""
        logger.debug("RAG 기반 응답 생성 시작")

        # 기술적 내용(코드, SQL, Docker 등) 감지
        is_technical = False
        tech_keywords = ["코드", "프로그래밍", "sql", "쿼리", "docker", "langgraph",
                         "함수", "클래스", "알고리즘", "python", "javascript", "java"]

        # 간단한 키워드 기반 감지
        if any(keyword in self.rqa.question.lower() for keyword in tech_keywords):
            is_technical = True
            logger.debug("기술적 내용 키워드 감지됨")

        # 코드 예제 요청 감지
        if "예제" in self.rqa.question and any(tech in self.rqa.question.lower() for tech in tech_keywords):
            is_technical = True
            logger.debug("코드 예제 요청 감지됨")

        # 기술적 내용이면 Claude로 변경
        if is_technical and llm_type != "Claude":
            claude_llm = self.llm_selector.models.get('Claude')
            if claude_llm:
                selected_llm = claude_llm
                llm_type = "Claude"
                logger.debug("기술적 내용 감지: Claude 모델로 전환")

        if self.related_docs:
            search_text = " ".join(self.related_docs)

            # 프롬프트 선택 (기술적 내용과 비기술적 내용 구분)
            if is_technical:
                prompt = ChatPromptTemplate.from_messages([
                    ("system", """기술 문서와 코드를 다루는 전문 어시스턴트입니다. 
                    코드, 프로그래밍 예제, SQL, Docker 등의 기술적 내용은 절대 요약하지 않고 
                    전체 내용을 그대로 제공합니다. 모든 코드는 완전한 형태로 보존하며, 
                    주석과 들여쓰기도 유지합니다. 예제 코드는 실행 가능한 완전한 형태로 제공합니다."""),
                    ("system", "이전 대화 내용:\n{history}"),
                    ("human", "{input}"),
                    ("human", "참고 정보: {context}")
                ])
            else:
                prompt = ChatPromptTemplate.from_messages([
                    ("system", "전문 리서치 어시스턴트입니다."),
                    ("system", "이전 대화 내용:\n{history}"),
                    ("human", "{input}"),
                    ("human", "참고 정보: {context}")
                ])

            try:
                response = selected_llm(prompt.format(
                    input=self.rqa.question,
                    context=search_text,
                    history=conversation_history
                ))

                if hasattr(response, 'content'):
                    return response.content
                else:
                    return str(response)
            except Exception as e:
                logger.error(f"RAG 응답 생성 중 오류: {str(e)}")
                return "내부 문서 기반 응답 생성 중 오류가 발생했습니다."
        else:
            # 관련 문서가 없을 때의 프롬프트
            if is_technical:
                prompt = ChatPromptTemplate.from_messages([
                    ("system", """기술 문서와 코드를 다루는 전문 어시스턴트입니다.
                    코드 예제 요청 시 완전하고 실행 가능한 코드를 제공합니다.
                    프로그래밍, SQL, Docker 등의 예제는 절대 요약하지 않고 완전한 형태로 제공합니다.
                    모든 코드는 실행 가능하도록 필요한 import 문과 함께 제공합니다."""),
                    ("system", "이전 대화 내용:\n{history}"),
                    ("human", "{question}")
                ])
            else:
                prompt = ChatPromptTemplate.from_messages([
                    ("system", "내부 데이터 기반 리서치 어시스턴트입니다."),
                    ("system", "이전 대화 내용:\n{history}"),
                    ("human", "{question}")
                ])

            try:
                response = selected_llm(prompt.format(
                    question=self.rqa.question,
                    history=conversation_history
                ))

                if hasattr(response, 'content'):
                    return response.content
                else:
                    return str(response)
            except Exception as e:
                logger.error(f"RAG 응답 생성 중 오류: {str(e)}")
                return "내부 문서 기반 응답 생성 중 오류가 발생했습니다."

    def generate_hybrid_response(self, selected_llm, llm_type, conversation_history):
        """하이브리드(RAG + Agent) 응답 생성"""
        logger.debug("하이브리드 응답 생성 시작")

        # 기술적 내용 감지
        is_technical = self._is_technical_content(self.rqa.question)

        # 기술적 내용이면 Claude로 변경 시도
        if is_technical and llm_type != "Claude":
            logger.debug("기술적 내용 감지: Claude 모델로 전환 시도")
            claude_llm = self.llm_selector.models.get('Claude')
            if claude_llm:
                selected_llm = claude_llm
                llm_type = "Claude"
                logger.debug("Claude 모델로 전환 완료")

        if not self.related_docs and not self.agent_search_results:
            # 둘 다 결과가 없는 경우 기본 응답
            prompt = ChatPromptTemplate.from_messages([
                ("system", "전문 리서치 어시스턴트입니다."),
                ("system", "이전 대화 내용:\n{history}"),
                ("human", "{question}")
            ])

            try:
                response = selected_llm(prompt.format(
                    question=self.rqa.question,
                    history=conversation_history
                ))

                if hasattr(response, 'content'):
                    return response.content
                else:
                    return str(response)
            except Exception as e:
                logger.error(f"기본 응답 생성 중 오류: {str(e)}")
                return "질문에 대한 관련 정보를 찾을 수 없습니다. 다른 질문을 해보세요."

        # 내부 문서와 외부 검색 결과 포맷팅
        context = " ".join(self.related_docs) if self.related_docs else "관련 내부 문서가 없습니다."
        formatted_search_results = self._format_search_results(self.agent_search_results)

        # 기술적 내용이면 특별 프롬프트 사용, 아니면 일반 프롬프트 사용
        if is_technical:
            prompt = self.get_technical_prompt_template(llm_type)
            logger.debug("기술적 내용 전용 프롬프트 사용")
        else:
            prompt = self.get_hybrid_prompt_template(llm_type)

        try:
            response = selected_llm(prompt.format(
                input=self.rqa.question,
                context=context,
                search_results=formatted_search_results,
                history=conversation_history
            ))

            if hasattr(response, 'content'):
                return response.content
            else:
                return str(response)
        except Exception as e:
            logger.error(f"하이브리드 응답 생성 중 오류: {str(e)}")
            return "종합적인 응답 생성 중 오류가 발생했습니다."

    def cleanup(self):
        """리소스 정리"""
        if self.mongo_client:
            self.mongo_client.close()

    def execute_searches(self):
        """RAG와 Agent 검색을 순차적으로 실행"""
        # 1. 내부 벡터 검색 실행
        self.perform_vector_search()

        # 2. 외부 검색 실행
        self.perform_external_search()

        logger.debug(f"검색 완료 - RAG 신뢰도: {self.rag_confidence:.2f}, 소스 수: {len(self.rag_sources)}")
        logger.debug(f"검색 완료 - Agent 신뢰도: {self.agent_confidence:.2f}, 검색 결과 수: {len(self.agent_search_results)}")

    def generate_responses(self, selected_llm, llm_type, conversation_history):
        """RAG와 Agent 응답을 순차적으로 생성"""
        # 1. RAG 응답 생성
        if self.rag_confidence > 0.3:  # 신뢰도가 일정 수준 이상일 때만 생성
            self.rag_response = self.generate_rag_response(selected_llm, llm_type, conversation_history)
            logger.debug("RAG 응답 생성 완료")
        else:
            self.rag_response = ""
            logger.debug("RAG 신뢰도가 낮아 응답 생성 건너뜀")

        # 2. Agent 응답 생성
        if self.agent_confidence > 0.3:  # 신뢰도가 일정 수준 이상일 때만 생성
            self.agent_response = self.generate_agent_response(selected_llm, llm_type, conversation_history)
            logger.debug("Agent 응답 생성 완료")
        else:
            self.agent_response = ""
            logger.debug("Agent 신뢰도가 낮아 응답 생성 건너뜀")

    def decide_best_response(self):
        """최적의 응답 방식 결정"""
        # 기본은 하이브리드
        response_mode = "hybrid"

        # 내부 문서 결과가 충분하고 외부 검색 결과가 없거나 적은 경우
        if len(self.rag_sources) >= 3 and len(self.agent_search_results) <= 1:
            if self.rag_confidence > 0.7:
                response_mode = "rag"
                logger.debug("내부 문서 결과가 충분하여 RAG 방식 선택")

        # 외부 검색 결과가 풍부하고 내부 문서 결과가 없거나 적은 경우
        elif len(self.agent_search_results) >= 3 and len(self.rag_sources) <= 1:
            if self.agent_confidence > 0.7:
                response_mode = "agent"
                logger.debug("외부 검색 결과가 풍부하여 Agent 방식 선택")

        # 시간적 키워드가 있는 경우 Agent에 높은 가중치
        temporal_keywords = ["오늘", "최근", "지금", "현재", "이번", "어제"]
        if any(kw in self.rqa.question for kw in temporal_keywords):
            if self.agent_confidence > 0.5:
                if response_mode == "hybrid":
                    logger.debug("시간 관련 키워드 감지, Agent 가중치 증가")
                    self.agent_confidence += 0.2

        # 두 결과 모두 충분히 좋은 경우 하이브리드 유지
        if self.rag_confidence > 0.6 and self.agent_confidence > 0.6:
            response_mode = "hybrid"
            logger.debug("RAG와 Agent 모두 신뢰도가 충분히 높아 하이브리드 방식 유지")

        logger.debug(f"최종 선택된 응답 방식: {response_mode}")
        return response_mode

    def get_file_by_name(self, filename: str, files: list = None) -> dict:
        """
        파일명으로 파일 정보를 가져옵니다.

        Args:
            filename (str): 파일명
            files (list, optional): 파일 목록(없으면 새로 조회)

        Returns:
            dict: 파일 정보 또는 None
        """
        if files is None:
            files = self.get_user_files()

        for file in files:
            if file["filename"] == filename:
                return file
        return None

    def _get_file_emoji(self, filename):
        """파일 유형에 따른 이모지 선택"""
        if '.' not in filename:
            return "📄"

        ext = filename.split('.')[-1].lower()

        if ext in ['pdf']:
            return "📕"
        elif ext in ['doc', 'docx']:
            return "📝"
        elif ext in ['xls', 'xlsx', 'csv']:
            return "📊"
        elif ext in ['ppt', 'pptx']:
            return "📊"
        elif ext in ['txt']:
            return "📄"
        elif ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp']:
            return "🖼️"
        elif ext in ['mp3', 'wav', 'ogg']:
            return "🎵"
        elif ext in ['mp4', 'avi', 'mov', 'wmv']:
            return "🎬"
        elif ext in ['zip', 'rar', '7z']:
            return "🗜️"
        else:
            return "📁"


    def _get_file_type(self, filename):
        """파일 유형 이름 반환"""
        if '.' not in filename:
            return "일반 파일"

        ext = filename.split('.')[-1].lower()

        types = {
            'pdf': 'PDF 문서',
            'doc': 'Word 문서',
            'docx': 'Word 문서',
            'xls': 'Excel 스프레드시트',
            'xlsx': 'Excel 스프레드시트',
            'csv': 'CSV 데이터',
            'ppt': 'PowerPoint 프레젠테이션',
            'pptx': 'PowerPoint 프레젠테이션',
            'txt': '텍스트 파일',
            'jpg': '이미지 파일',
            'jpeg': '이미지 파일',
            'png': '이미지 파일',
            'gif': '이미지 파일',
            'mp3': '오디오 파일',
            'wav': '오디오 파일',
            'mp4': '비디오 파일',
            'avi': '비디오 파일',
            'zip': '압축 파일',
            'rar': '압축 파일'
        }

        return types.get(ext, f"{ext.upper()} 파일")

    def _estimate_remaining_time(self, file_info):
        """남은 처리 시간 예상"""
        extract_rate = file_info.get("extract_page_rate", 0) or 0
        embedding_rate = file_info.get("embedding_rate", 0) or 0

        # 간단한 예측 로직
        if extract_rate < 50:
            return "예상 완료 시간은 5-10분 이내입니다."
        elif extract_rate >= 50 and embedding_rate < 30:
            return "잠시 후 완료될 예정입니다 (약 3-5분)."
        elif embedding_rate >= 30 and embedding_rate < 70:
            return "곧 완료될 예정입니다 (약 1-3분)."
        else:
            return "거의 완료 단계입니다 (1분 이내)."


    def _generate_progress_bar(self, percentage, length=10):
        """
        퍼센트 기반의 진행률 바 생성

        Args:
            percentage: 진행률 (0-100)
            length: 진행률 바의 길이(문자 수)

        Returns:
            str: 진행률 바 문자열
        """
        filled = int((percentage / 100) * length)
        empty = length - filled
        return '█' * filled + '░' * empty


    def generate_specific_file_response(self, file_info, request_type):
        """특정 파일 정보 응답 생성 (마크다운 형식)"""

        file_name = file_info['filename']
        file_emoji = self._get_file_emoji(file_name)  # 파일 타입에 따른 이모지 선택

        if request_type == "요약":
            # 파일 요약 정보 제공
            if file_info["summary"]:
                response = f"# {file_emoji} {file_name} - 요약 정보\n\n"
                response += f"{file_info['summary']}\n\n"
                response += f"> 이 요약은 AI가 자동으로 생성한 것으로, 원본 내용과 차이가 있을 수 있습니다."
            else:
                response = f"# {file_emoji} {file_name}\n\n"
                response += "⚠️ 죄송합니다. 이 파일의 요약 정보가 아직 준비되지 않았습니다.\n\n"

                # 처리 상태에 따른 안내 메시지
                if file_info["status"] != "done" and file_info["status"] != "complete":
                    response += "파일 처리가 아직 완료되지 않았습니다. 잠시 후 다시 시도해 주세요."
                else:
                    response += "파일 요약 생성에 문제가 발생했습니다. 다른 질문을 해보세요."

        elif request_type == "내용":
            # 파일 내용 관련 응답
            response = f"# {file_emoji} {file_name} - 내용 안내\n\n"
            response += "파일 내용에 대해 구체적인 질문을 해주시면 관련 정보를 찾아 답변해 드립니다.\n\n"
            response += "## 질문 예시:\n\n"

            # 파일 확장자에 따라 적절한 질문 예시 제공
            file_ext = file_name.split('.')[-1].lower() if '.' in file_name else ''

            if file_ext in ['pdf', 'docx', 'doc', 'txt']:
                response += "- 이 문서에서 가장 중요한 내용은 무엇인가요?\n"
                response += "- 이 문서에 A와 B에 대한 설명이 있나요?\n"
                response += "- 이 문서의 핵심 주장은 무엇인가요?\n"
            elif file_ext in ['xlsx', 'xls', 'csv']:
                response += "- 이 데이터의 평균 수치는 얼마인가요?\n"
                response += "- 가장 높은 값을 가진 항목은 무엇인가요?\n"
                response += "- 2023년과 2024년의 데이터를 비교해 주세요.\n"
            else:
                response += "- 이 파일에서 주요 내용은 무엇인가요?\n"
                response += "- A에 대한 정보가 있나요?\n"
                response += "- 이 파일에서 가장 중요한 부분을 알려주세요.\n"

        elif request_type == "상태":
            # 파일 처리 상태 정보
            status_msg = "✅ 처리 완료" if file_info["status"] == "done" or file_info["status"] == "complete" else "⏳ 처리 중"

            response = f"# {file_emoji} {file_name} - 처리 상태\n\n"
            response += f"**현재 상태**: {status_msg}\n\n"

            if file_info["extract_page_rate"] is not None:
                extract_rate = file_info["extract_page_rate"]
                progress_bar = self._generate_progress_bar(extract_rate)
                response += f"## 텍스트 추출\n"
                response += f"{progress_bar} **{extract_rate}%**\n\n"

            if file_info["embedding_rate"] is not None:
                embedding_rate = file_info["embedding_rate"]
                progress_bar = self._generate_progress_bar(embedding_rate)
                response += f"## 임베딩 진행률\n"
                response += f"{progress_bar} **{embedding_rate}%**\n\n"

            # 상태에 따른 메시지
            if file_info["status"] == "done" or file_info["status"] == "complete":
                response += "✨ **파일 처리가 완료되었습니다**. 이 파일에 대한 질문을 하실 수 있습니다.\n"
            else:
                remaining_time = self._estimate_remaining_time(file_info)
                response += f"⏱️ **파일 처리가 진행 중입니다**. {remaining_time}\n"
                response += "> 처리가 완료되면 파일 내용에 대한 질문에 더 정확히 답변할 수 있습니다.\n"

        else:  # 기타 정보
            # 파일 일반 정보
            file_size = self.format_file_size(file_info["filesize"])
            status_msg = "✅ 처리 완료" if file_info["status"] == "done" or file_info["status"] == "complete" else "⏳ 처리 중"

            response = f"# {file_emoji} {file_name}\n\n"
            response += f"## 기본 정보\n\n"
            response += f"- **파일 유형**: {self._get_file_type(file_name)}\n"
            response += f"- **상태**: {status_msg}\n"
            response += f"- **크기**: {file_size}\n"
            response += f"- **업로드 일시**: {file_info['uploaded_formatted']}\n\n"

            if file_info["extract_page_rate"] is not None or file_info["embedding_rate"] is not None:
                response += "## 처리 상태\n\n"

                if file_info["extract_page_rate"] is not None:
                    extract_rate = file_info["extract_page_rate"]
                    progress_bar = self._generate_progress_bar(extract_rate)
                    response += f"- **추출 진행률**: {progress_bar} {extract_rate}%\n"

                if file_info["embedding_rate"] is not None:
                    embedding_rate = file_info["embedding_rate"]
                    progress_bar = self._generate_progress_bar(embedding_rate)
                    response += f"- **임베딩 진행률**: {progress_bar} {embedding_rate}%\n\n"

            if file_info["summary"]:
                response += "## 요약 정보\n\n"
                response += f"{file_info['summary']}\n\n"
                response += "> 이 요약은 AI가 자동으로 생성한 것으로, 원본 내용과 차이가 있을 수 있습니다.\n"

            response += "\n## 활용 방법\n\n"
            response += "이 파일에 대해 다음과 같은 정보를 요청할 수 있습니다:\n"
            response += "- '요약': 파일 내용의 요약 정보\n"
            response += "- '내용': 파일의 특정 정보 검색 안내\n"
            response += "- '상태': 파일 처리 진행 상황\n"

        return response

    def generate_file_list_response(self, files):
        """파일 목록 응답 생성"""
        if not files:
            return "현재 등록된 파일이 없습니다. 파일을 업로드하면 분석에 활용할 수 있습니다."

        response = f"# 파일 목록\n\n현재 **{len(files)}개**의 파일이 등록되어 있습니다:\n\n"

        for idx, file in enumerate(files, 1):
            status_msg = "✅ 처리 완료" if file["status"] == "complete" else "⏳ 처리 중"
            file_size = self.format_file_size(file["filesize"])

            response += f"## {idx}. {file['filename']}\n\n"
            response += f"- **상태**: {status_msg}\n"
            response += f"- **크기**: {file_size}\n"
            response += f"- **업로드 일시**: {file['uploaded_formatted']}\n"

            if file["summary"]:
                # 요약 정보가 너무 길면 잘라서 표시
                summary = file["summary"]
                if len(summary) > 100:
                    summary = summary[:100] + "..."
                response += f"- **요약**: {summary}\n"

            # 파일 처리 진행률 표시
            if file["extract_page_rate"] is not None:
                extract_rate = file["extract_page_rate"]
                # 진행률 바 생성 (10 단계)
                progress_bar = self._generate_progress_bar(extract_rate)
                response += f"- **추출 진행률**: {progress_bar} {extract_rate}%\n"

            if file["embedding_rate"] is not None:
                embedding_rate = file["embedding_rate"]
                # 진행률 바 생성 (10 단계)
                progress_bar = self._generate_progress_bar(embedding_rate)
                response += f"- **임베딩 진행률**: {progress_bar} {embedding_rate}%\n"

            if idx < len(files):
                response += "\n---\n\n"

        response += "\n\n> **안내**: 특정 파일에 대해 더 알고 싶으시면 파일명을 언급해 주세요."
        return response


    def generate(self):
        """하이브리드 응답 스트림 생성"""
        try:
            # 사용자 검증
            if not self.initialize():
                yield json.dumps({"error": "사용자 검증 실패", "type": "error"}) + "\n"
                return

            # MongoDB 설정
            llm_chat_history_db, user_sessions_coll = self.setup_mongodb()

            # 세션 ID 전송
            yield json.dumps({"session_id": self.session_id, "type": "session"}) + "\n"

            # 사용자 파일 목록 조회
            user_files = self.get_user_files()

            # 특수 응답 플래그 및 내용 변수 초기화
            special_response = None
            is_file_list_request = False
            is_specific_file_request = False

            # 특수 요청 감지 (파일 목록 등)
            if self.intent_analyzer.is_file_list_request(self.rqa.question):
                logger.debug("파일 목록 요청 감지됨")
                # 파일 목록 응답 생성 (조기 반환하지 않고 저장만 함)
                special_response = self.generate_file_list_response(user_files)
                is_file_list_request = True

            # 파일 관련 특정 요청 감지
            if not is_file_list_request and user_files:
                specific_file_request = self.intent_analyzer.get_specific_file_info(
                    self.rqa.question, user_files
                )
                if specific_file_request.get("is_specific_file", False):
                    file_name = specific_file_request.get("file_name", "")
                    request_type = specific_file_request.get("request_type", "정보")

                    # 파일 정보 가져오기
                    file_info = self.get_file_by_name(file_name, user_files)

                    if file_info:
                        logger.debug(f"특정 파일 요청 감지: {file_name}, 요청 유형: {request_type}")
                        # 특정 파일 응답 생성 (조기 반환하지 않고 저장만 함)
                        special_response = self.generate_specific_file_response(file_info, request_type)
                        is_specific_file_request = True

            # 대화 기록 가져오기
            mongochat_history = MongoDBChatMessageHistory(
                session_id=self.session_id,
                connection_string=MONGO_CONN_STRING,
                database_name=CHAT_HISTORY_SOURCE_DB,
                collection_name=self.user_code,
            )

            # 이전 대화 내용 가져오기
            recent_messages = history_manager.get_recent_messages(mongochat_history)
            conversation_history = history_manager.format_history_for_prompt(recent_messages)

            # LLM 선택 및 정보 가져오기
            selected_llm = llm_selector.select_llm(self.rqa.question)
            llm_type = llm_selector.get_llm_info(selected_llm)
            logger.debug(f"선택된 LLM: {llm_type}")

            # 하이브리드 모드 시작 메시지
            yield json.dumps({
                "content": "🔄 정보를 수집 중입니다...\n",
                "type": "chunk",
                "method": "hybrid"
            }) + "\n"

            # 1단계: RAG와 Agent 검색을 순차적으로 실행 (모든 경우에 수행)
            self.execute_searches()

            # 검색 소스 메타데이터 전송
            yield json.dumps({
                "sources": self.rag_sources,
                "search_results": self.agent_search_results,
                "type": "metadata"
            }) + "\n"

            # 특수 케이스 처리 - 파일 목록이나 특정 파일 응답이 있는 경우
            if is_file_list_request or is_specific_file_request:
                # 특수 응답 스트리밍
                for chunk in special_response.split("\n"):
                    if chunk:
                        yield json.dumps({"content": chunk + "\n", "type": "chunk"}) + "\n"

                # 에이전트 검색 결과가 있으면 추가 정보 제공
                if self.agent_search_results and len(self.agent_search_results) > 0:
                    yield json.dumps({
                        "content": "\n\n## 🔍 관련 외부 정보\n\n",
                        "type": "chunk"
                    }) + "\n"

                    # 에이전트 기반 정보 생성 및 스트리밍
                    formatted_search_results = self._format_search_results(self.agent_search_results)
                    prompt = ChatPromptTemplate.from_messages([
                        ("system", f"""당신은 파일 정보와 관련된 추가 정보를 제공하는 어시스턴트입니다. 
                        사용자의 질문 '{self.rqa.question}'에 대해 파일 정보를 이미 제공했습니다.
                        이제 관련된 외부 검색 결과를 기반으로 추가 정보나 맥락을 간결하게 제공해 주세요.
                        파일 내용이나 정보를 반복하지 말고, 확장된 맥락이나 관련 최신 정보만 제공하세요."""),
                        ("human", f"외부 검색 결과: {formatted_search_results}")
                    ])

                    agent_response = ""
                    for chunk in selected_llm.stream(prompt.format(
                            question=self.rqa.question,
                            search_results=formatted_search_results
                    )):
                        content = chunk.content if hasattr(chunk, 'content') else str(chunk)
                        agent_response += content
                        yield json.dumps({"content": content, "type": "chunk"}) + "\n"

                    # MongoDB에 특수 응답 + 에이전트 응답 저장
                    full_response = special_response + "\n\n## 관련 외부 정보\n\n" + agent_response
                    self.save_to_mongodb(user_sessions_coll, full_response)
                else:
                    # 에이전트 검색 결과가 없으면 특수 응답만 저장
                    self.save_to_mongodb(user_sessions_coll, special_response)

                # 완료 시그널
                yield json.dumps({"type": "done"}) + "\n"
                return

            # 일반 질문에 대한 처리 - 기존 코드대로 진행
            # 최적의 응답 방식 결정
            response_mode = self.decide_best_response()

            # 결정된 방식에 따라 응답 생성
            full_response = ""

            if response_mode == "rag":
                # RAG 방식으로 스트리밍
                if self.related_docs:
                    search_text = " ".join(self.related_docs)
                    prompt = self.get_rag_prompt_template(llm_type)

                    # 방식 알림
                    yield json.dumps({
                        "content": "💡 내부 문서를 기반으로 답변합니다...\n\n",
                        "type": "chunk",
                        "method": "rag"
                    }) + "\n"

                    # 응답 스트리밍
                    for chunk in selected_llm.stream(prompt.format(
                            input=self.rqa.question,
                            context=search_text,
                            history=conversation_history
                    )):
                        content = chunk.content if hasattr(chunk, 'content') else str(chunk)
                        full_response += content
                        yield json.dumps({"content": content, "type": "chunk", "method": "rag"}) + "\n"
                else:
                    # 관련 문서가 없는 경우 간단한 프롬프트 사용
                    prompt = ChatPromptTemplate.from_messages([
                        ("system", "내부 데이터 기반 리서치 어시스턴트입니다."),
                        ("system", "이전 대화 내용:\n{history}"),
                        ("human", "{question}")
                    ])

                    for chunk in selected_llm.stream(prompt.format(
                            question=self.rqa.question,
                            history=conversation_history
                    )):
                        content = chunk.content if hasattr(chunk, 'content') else str(chunk)
                        full_response += content
                        yield json.dumps({"content": content, "type": "chunk", "method": "rag"}) + "\n"

                # MongoDB에 RAG 응답 저장
                self.save_to_mongodb(user_sessions_coll, full_response, "rag")

            elif response_mode == "agent":
                # Agent 방식으로 스트리밍
                formatted_search_results = self._format_search_results(self.agent_search_results)
                prompt = self.get_agent_prompt_template(llm_type)

                # 방식 알림
                yield json.dumps({
                    "content": "🔍 외부 검색 결과를 기반으로 답변합니다...\n\n",
                    "type": "chunk",
                    "method": "agent"
                }) + "\n"

                # 응답 스트리밍
                for chunk in selected_llm.stream(prompt.format(
                        input=self.rqa.question,
                        search_results=formatted_search_results,
                        history=conversation_history
                )):
                    content = chunk.content if hasattr(chunk, 'content') else str(chunk)
                    full_response += content
                    yield json.dumps({"content": content, "type": "chunk", "method": "agent"}) + "\n"

                # MongoDB에 Agent 응답 저장
                self.save_to_mongodb(user_sessions_coll, full_response, "agent")

            else:  # 하이브리드
                # 하이브리드 방식으로 스트리밍
                context = " ".join(self.related_docs) if self.related_docs else "관련 내부 문서가 없습니다."
                formatted_search_results = self._format_search_results(self.agent_search_results)
                prompt = self.get_hybrid_prompt_template(llm_type)

                # 방식 알림
                yield json.dumps({
                    "content": "🔄 내부 문서와 외부 검색 결과를 모두 활용하여 답변합니다...\n\n",
                    "type": "chunk",
                    "method": "hybrid"
                }) + "\n"

                # 응답 스트리밍
                for chunk in selected_llm.stream(prompt.format(
                        input=self.rqa.question,
                        context=context,
                        search_results=formatted_search_results,
                        history=conversation_history
                )):
                    content = chunk.content if hasattr(chunk, 'content') else str(chunk)
                    full_response += content
                    yield json.dumps({"content": content, "type": "chunk", "method": "hybrid"}) + "\n"

                # MongoDB에 하이브리드 응답 저장
                self.save_to_mongodb(user_sessions_coll, full_response, "hybrid")

            # 완료 시그널
            yield json.dumps({"type": "done"}) + "\n"

        except Exception as e:
            logger.error(f"하이브리드 응답 생성 중 오류: {str(e)}")
            yield json.dumps({"error": str(e), "type": "error"}) + "\n"

        finally:
            self.cleanup()

    def format_file_size(self, size_in_bytes):
        """파일 크기를 읽기 쉬운 형식으로 변환"""
        if not size_in_bytes:
            return "크기 정보 없음"

        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_in_bytes < 1024.0:
                return f"{size_in_bytes:.2f} {unit}"
            size_in_bytes /= 1024.0
        return f"{size_in_bytes:.2f} TB"

@app.post("/chatapi/rqa_stream/",
          summary="스트리밍 RAG QnA 기능",
          description="스트리밍 방식으로 답변을 제공합니다.",
          response_description="스트리밍 텍스트 응답")
def rpa_stream(rqa: ChatRQA, token_data: dict = Depends(verify_token)):
    """
    스트리밍 RAG QnA 기능
    email : 접속한 사용자 email <br>
    question: 데이터베이스 내용에 기반한 질문 <br>
    session_id : 대화 History id <br>
    isnewsession : 새로운 대화일 경우 : true로 설정 session_id는 무시됨 <br>
    false로 설정시 session_id 필수 기입 <br>
    """

    # 질문 분석 로깅
    logger.info(f"질문 수신: {rqa.question[:100]}{'...' if len(rqa.question) > 100 else ''}")

    # 하이브리드 ResponseStreamer 생성
    streamer = HybridResponseStreamer(rqa, token_data)

    return StreamingResponse(streamer.generate(), media_type="text/event-stream")


def process_tool_calls(question):
    """도구 호출 처리 로직"""
    try:
        logger.debug(f"Question for search: {question}")
        tool_call_results = searchchain_tools.invoke(question)
        logger.debug(f"Tool call results: {tool_call_results}")

        search_results = []
        if tool_call_results:
            for result in tool_call_results:
                if isinstance(result, dict) and "args" in result:
                    # Tavily 검색
                    tavily_results = web_search(result["args"])
                    # Serper 검색
                    serper_results = serper_search(result["args"])

                    try:
                        # Tavily 결과 처리
                        parsed_tavily = json.loads(tavily_results)
                        for item in parsed_tavily:
                            search_results.append({
                                "title": item.get("content", ""),
                                # "content": item.get("content", ""),
                                "url": item.get("url", ""),
                                "source": "Tavily"
                            })

                        # Serper 결과 처리
                        parsed_serper = json.loads(serper_results)
                        for item in parsed_serper:
                            search_results.append({
                                "title": item.get("title", ""),
                                "content": item.get("content", ""),
                                "url": item.get("url", ""),
                                "source": "Serper"
                            })
                    except json.JSONDecodeError as e:
                        logger.error(f"Error parsing search results: {str(e)}")

        logger.debug(f"Processed search results: {search_results}")
        return search_results

    except Exception as e:
        logger.error(f"Search processing error: {str(e)}")
        return []


def send_json_post_qeury(url_path, method, body: dict):
    url = f"{url_path}/{method}"
    headers = {'Content-Type': 'application/json', 'charset': 'UTF-8', 'Accept': '*/*'}

    try:
        response = requests.post(url, headers=headers, data=json.dumps(body, ensure_ascii=False, indent="\t"))
        if response.status_code == 200:
            rtn_json = response.json()
            return {"status": "ok", "msg": rtn_json}

    except Exception as e:
        print(e)
        logger.error(str(e))
        return {"status":"error","msg": str(e)}

def get_doc_id(userid, filename):

    sql = f'SELECT `id`, userid, filename, status FROM tb_llm_doc where userid="{userid}" and filename="{filename}"'  # 대상 파일 선택
    try:
        mariadb_conn = pymysql.connect(
            user=opds_system_db_info["id"],
            password=opds_system_db_info["pwd"],
            database=opds_system_db_info["database"],
            host=opds_system_db_info["address"],
            port=opds_system_db_info["port"]
        )
        cs = mariadb_conn.cursor()
        cs.execute(sql)
        rs = cs.fetchall()
        filename_df = pd.DataFrame(rs, columns=['id', 'userid', 'filename', 'status'])
        cs.close()
        mariadb_conn.close()

        for row in filename_df.iterrows():
            id = row[1]['id']
            return id

    except Exception as e:
        logger.error(e)
        return None

def get_code_byemail(email):
    rtn_json = send_json_post_qeury(url_path=MANAGEMENT_SERVICE, method='get_usercode', body={"email": email})
    data_json = rtn_json['msg']
    auth = data_json['auth']
    if auth is True:
        return data_json['user_code']
    else:
        return None


def insert_fileinfo(userid, file_name, filesize):
    try:
        with mariadb_manager.get_session() as db:
            db.execute(
                text("""DELETE FROM tb_llm_doc 
                                  WHERE filename=:filename AND userid=:userid"""),
                {'filename': file_name, 'userid': userid}
            )
            logger.debug("DELETE 쿼리 성공")
            status = 'upload'
            uploaded = datetime.now(timezone('Asia/Seoul')).strftime("%Y-%m-%d %H:%M:%S.%f")

            insert_query = text("""INSERT INTO tb_llm_doc 
                                 (filename, filesize, status, uploaded, userid)
                                 VALUES (:filename, :filesize, :status, :uploaded, :userid)""")

            logger.debug(
                f"INSERT 파라미터: filename={file_name}, filesize={filesize}, status={status}, uploaded={uploaded}, userid={userid}")

            db.execute(insert_query, {
                'filename': file_name,
                'filesize': filesize,
                'status': status,
                'uploaded': uploaded,
                'userid': userid
            })
            logger.debug("INSERT 쿼리 성공")
            result = db.execute(
                text("""SELECT id FROM tb_llm_doc 
                                WHERE userid=:userid AND filename=:filename"""),
                {'userid': userid, 'filename': file_name}
            )
            doc_id = result.scalar()
            return doc_id

    except Exception as e:
        logger.error(f"Error inserting file info: {str(e)}")
        return None


@app.post("/chatapi/files/upload/single/",
          response_model=UploadResponse,
          summary="JWT 인증이 필요한 단일 파일 업로드",
          description="JWT 토큰 인증 후 이메일 주소와 단일 파일을 업로드합니다.")
async def upload_single_file(
        email: str = Form(..., description="사용자의 이메일 주소", examples="test@gmail.com"),
        upload_file: UploadFile = File(..., description="업로드할 파일"),
        token_data: dict = Depends(verify_token)
):
    """
    JWT 인증이 필요한 단일 파일 업로드 API
    """
    try:
        if not "@" in email:
            raise HTTPException(
                status_code=400,
                detail="올바른 이메일 주소를 입력해주세요"
            )

        file_responses = []
        total_size = 0
        code = get_code_byemail(email)

        file_path = os.path.join(UPLOAD_DIRECTORY, upload_file.filename)
        dir_path = os.path.dirname(file_path)
        os.makedirs(dir_path, exist_ok=True)

        content = await upload_file.read()
        with open(file_path, "wb") as buffer:
            buffer.write(content)
            file_size = len(content)
            total_size += file_size

        # Rest of your file processing code...
        try:
            client = Minio(minio_address,
                           access_key=accesskey,
                           secret_key=secretkey, secure=False)
            client.fput_object(code, upload_file.filename, file_path)
            stat = client.stat_object(code, upload_file.filename)
            object_size = stat.size
            logger.debug(f"Minio pub finish{email}, {upload_file.filename} {object_size}")

            doc_id = insert_fileinfo(code, upload_file.filename, object_size)
            if doc_id is None:
                logger.error(f"{upload_file.filename} register error")
                raise Exception("None")
            prep_msg = json.dumps({'user_email': email, 'doc_id': doc_id, 'file_name': upload_file.filename})

            credentials = pika.PlainCredentials(mqtt_id, mqtt_pwd)
            param = pika.ConnectionParameters(mqtt_address, mqtt_port, mqtt_virtualhost, credentials)
            connection = pika.BlockingConnection(param)

            OPDS_CHANNEL = connection.channel()
            OPDS_CHANNEL.queue_declare(queue=OPDS_RREP_REQ_Q)
            OPDS_CHANNEL.basic_publish(exchange='',
                                       routing_key=OPDS_RREP_ROUTE,
                                       body=prep_msg)
            OPDS_CHANNEL.close()
            logger.debug(f"Preprocess MSG Published{email}, {doc_id}, {upload_file.filename}")
            logger.debug(str(prep_msg))
        except Exception as e:
            logger.error(e)

        file_responses.append(
            FileResponse(
                filename=upload_file.filename,
                file_size=file_size,
                content_type=upload_file.content_type
            )
        )

        return UploadResponse(
            email=email,
            files=file_responses,
            total_files=1,
            total_size=total_size
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"파일 업로드 중 오류가 발생했습니다: {str(e)}"
        )


@app.post("/chatapi/files/upload/",
          response_model=UploadResponse,
          summary="JWT 인증이 필요한 다중 파일 업로드",
          description="JWT 토큰 인증 후 이메일 주소와 여러 파일을 업로드합니다.")
async def upload_files(
        email: str = Form(..., description="사용자의 이메일 주소", examples="test@gmail.com"),
        upload_files: List[UploadFile] = File(..., description="업로드할 파일들"),
        token_data: dict = Depends(verify_token)
):
    """
    JWT 인증이 필요한 다중 파일 업로드 API
    Parameters:
    - **email**: 사용자 이메일 주소
    - **files**: 업로드할 파일 리스트
    - **token**: JWT 토큰 (Authorization 헤더)
    """
    # 토큰의 이메일과 요청의 이메일이 일치하는지 확인
    if token_data["sub"] != email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email in token does not match with request email"
        )

    try:
        if not "@" in email:
            raise HTTPException(
                status_code=400,
                detail="올바른 이메일 주소를 입력해주세요"
            )

        if not upload_files:
            raise HTTPException(
                status_code=400,
                detail="최소 하나 이상의 파일을 업로드해주세요"
            )

        file_responses = []
        total_size = 0
        code = get_code_byemail(email)
        logger.debug(f"user code: {code}")
        for upload_file in upload_files:
            file_path = os.path.join(UPLOAD_DIRECTORY, upload_file.filename)
            dir_path = os.path.dirname(file_path)
            os.makedirs(dir_path, exist_ok=True)

            with open(file_path, "wb") as buffer:
                content = await upload_file.read()
                buffer.write(content)
                file_size = len(content)
                total_size += file_size

            success_file_list = []
            logger.debug(f"File Path: {file_path}")
            try:
                client = Minio(minio_address,
                               access_key=accesskey,
                               secret_key=secretkey, secure=False)
                client.fput_object(code, upload_file.filename, file_path)
                stat = client.stat_object(code, upload_file.filename)
                object_size = stat.size
                logger.debug(f"Minio pub finish{email}, {upload_file.filename} {object_size}")

                doc_id = insert_fileinfo(code, upload_file.filename, object_size)
                prep_msg = json.dumps({'user_email': email, 'doc_id': doc_id, 'file_name': upload_file.filename})

                credentials = pika.PlainCredentials(mqtt_id, mqtt_pwd)
                param = pika.ConnectionParameters(mqtt_address, mqtt_port, mqtt_virtualhost, credentials)
                connection = pika.BlockingConnection(param)
                OPDS_CHANNEL = connection.channel()

                OPDS_CHANNEL.queue_declare(queue=OPDS_RREP_REQ_Q)
                OPDS_CHANNEL.basic_publish(exchange='',
                                           routing_key=OPDS_RREP_ROUTE,
                                           body=prep_msg)
                OPDS_CHANNEL.close()
                logger.debug(f"Preprocess MSG Published{email}, {doc_id}, {upload_file.filename}")
                logger.debug(str(prep_msg))
            except Exception as e:
                logger.error(e)

            file_responses.append(
                FileResponse(
                    filename=upload_file.filename,
                    file_size=file_size,
                    content_type=upload_file.content_type
                )
            )

        return UploadResponse(
            email=email,
            files=file_responses,
            total_files=len(upload_files),
            total_size=total_size
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"파일 업로드 중 오류가 발생했습니다: {str(e)}"
        )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=rest_config['port'])