import json

import yaml
import pika
from minio import Minio
from datetime import datetime
import pymysql
from pytz import timezone
import pandas as pd

with open('set.yaml') as f:
    config = yaml.load(f, Loader=yaml.FullLoader)

minio_info = config['minio']
minio_address = minio_info['address']
accesskey = minio_info['accesskey']
secretkey = minio_info['secretkey']

mqtt_info = config['mqtt']
mqtt_id = mqtt_info['id']
mqtt_pwd = mqtt_info['pwd']
mqtt_address = mqtt_info['address']
mqtt_port = mqtt_info['port']
mqtt_virtualhost = mqtt_info['virtualhost']

RABBITMQ_SVC_QUEUE = config['RABBITMQ_SVC_QUEUE']

opds_system_db = config['database']['opds_system_db']
mariadb_conn = pymysql.connect(
        user=opds_system_db["id"],
        password=opds_system_db["pwd"],
        database=opds_system_db["database"],
        host=opds_system_db["address"],
        port=opds_system_db["port"]
    )

credentials = pika.PlainCredentials(mqtt_id, mqtt_pwd)
param = pika.ConnectionParameters(mqtt_address, mqtt_port, mqtt_virtualhost, credentials)
connection = pika.BlockingConnection(param)

#amqp://guest:guest@222.239.231.95:20000 #MinIO에 EVENT 등록시 주소
MINIO_q_name = RABBITMQ_SVC_QUEUE['MINIO_Q_NAME']
MINIO_ex_name = RABBITMQ_SVC_QUEUE['MINIO_EXCHNAGE_NAME']
MINIO_r_key = RABBITMQ_SVC_QUEUE['MINIO_ROUTEKEY']

MINO_Channel = connection.channel()
MINO_Channel.queue_declare(queue=MINIO_q_name)
MINO_Channel.exchange_declare(exchange=MINIO_ex_name, exchange_type='direct')
MINO_Channel.queue_bind(queue=MINIO_q_name, exchange=MINIO_ex_name, routing_key=MINIO_r_key)

OPDS_RREP_REQ_Qname = RABBITMQ_SVC_QUEUE['PREPROCES_Q_NAME']
OPDS_RREP_REQ_Ex = RABBITMQ_SVC_QUEUE['PREPROCES_EXCHANGE_NAME']
OPDS_RREP_ROUTE = RABBITMQ_SVC_QUEUE['PREPROCES_ROUTEKEY']
OPDS_RREP = connection.channel()
OPDS_RREP.queue_declare(queue=OPDS_RREP_REQ_Qname)
OPDS_RREP.exchange_declare(exchange=OPDS_RREP_REQ_Ex, exchange_type='direct')
OPDS_RREP.queue_bind(queue=OPDS_RREP_REQ_Qname, exchange=OPDS_RREP_REQ_Ex, routing_key=OPDS_RREP_ROUTE)

OPDS_SUMMARY_REQ_Qname = RABBITMQ_SVC_QUEUE['SUMMARY_Q_NAME']
OPDS_SUMMARY_REQ_Ex = RABBITMQ_SVC_QUEUE['SUMMARY_EXCHANGE_NAME']
OPDS_SUMMARY_ROUTE = RABBITMQ_SVC_QUEUE['SUMMARY_ROUTE_KEY']
OPDS_SUMMARY = connection.channel()
OPDS_SUMMARY.queue_declare(queue=OPDS_SUMMARY_REQ_Qname)
OPDS_SUMMARY.exchange_declare(exchange=OPDS_SUMMARY_REQ_Ex, exchange_type='direct')
OPDS_SUMMARY.queue_bind(queue=OPDS_SUMMARY_REQ_Qname, exchange=OPDS_SUMMARY_REQ_Ex, routing_key=OPDS_SUMMARY_ROUTE)

OPDS_EMBEDDING_REQ_Qname = RABBITMQ_SVC_QUEUE['EMBEDDING_Q_NAME']
OPDS_EMBEDDING_REQ_Ex = RABBITMQ_SVC_QUEUE['EMBEDDING_EXCHANGE_NAME']
OPDS_EMBEDDING_ROUTE = RABBITMQ_SVC_QUEUE['EMBEDDING_ROUTE_KEY']
OPDS_EMBEDDING_Channel = connection.channel()
OPDS_EMBEDDING_Channel.queue_declare(queue=OPDS_EMBEDDING_REQ_Qname)
OPDS_EMBEDDING_Channel.exchange_declare(exchange=OPDS_EMBEDDING_REQ_Ex, exchange_type='direct')
OPDS_EMBEDDING_Channel.queue_bind(queue=OPDS_EMBEDDING_REQ_Qname, exchange=OPDS_EMBEDDING_REQ_Ex, routing_key=OPDS_EMBEDDING_ROUTE)

def get_userid_fromcode(user_code):
    opds_sysdb_conn = pymysql.connect(
        user=opds_system_db["id"],
        password=opds_system_db["pwd"],
        database=opds_system_db["database"],
        host=opds_system_db["address"],
        port=opds_system_db["port"]
    )
    sql = f'SELECT `id`, name FROM tb_user WHERE user_code="{user_code}"'  # 대상 파일 선택
    cs = opds_sysdb_conn.cursor()
    cs.execute(sql)
    rs = cs.fetchall()
    user_name_df = pd.DataFrame(rs, columns=['id', 'name'])
    cs.close()
    opds_sysdb_conn.close()

    if user_name_df.shape[0] == 1:
        user_name_df = user_name_df.iloc[0].to_dict()
        uname = user_name_df["name"]
        return  uname

def get_doc_id(userid, filename):
    sql = f'SELECT `id`, userid, filename, status FROM tb_llm_doc where userid="{userid}" and filename="{filename}"'  # 대상 파일 선택
    try:
        cs = mariadb_conn.cursor()
        cs.execute(sql)
        rs = cs.fetchall()
        filename_df = pd.DataFrame(rs, columns=['id', 'userid', 'filename', 'status'])
        cs.close()
        ids = []
        for row in filename_df.iterrows():
            id = row[1]['id']
            ids.append(id)
        return ids
    except Exception as e:
        print(e)


def insert_fileinfo(userid, file_name, filesize):
    doc_id = get_doc_id(userid, file_name)
    if len(doc_id) == 1:
        print(f'doc id {doc_id} exist')
        return doc_id
    else:
        sql = f"""INSERT INTO {opds_system_db["database"]}.tb_llm_doc (filename, filesize, status, uploaded, userid) 
                                    values (%s, %s, %s, %s, %s)"""
        cs = mariadb_conn.cursor()
        status = 'upload'
        uploaded = datetime.now(timezone('Asia/Seoul')).strftime("%Y-%m-%d %H:%M:%S.%f")
        cs.execute(sql, (file_name, filesize, status, uploaded, userid))
        mariadb_conn.commit()
        cs.close()
        new_doc_id = get_doc_id(userid, file_name)
        print(f'new doc id {doc_id} exist')
        return new_doc_id


client = Minio(minio_address,
               access_key=accesskey,
               secret_key=secretkey, secure=False)

dummy_list = []
dummy_list.append({"user_email":"theprismdata@gmail.com",
                    "file_name":"[KDI 연구보고서]/2014-05-정책효과성 증대를 위한 집행과학에 관한 연구.pdf"})

def get_usercode_fromid(user_email):
    opds_sysdb_conn = pymysql.connect(
        user=opds_system_db["id"],
        password=opds_system_db["pwd"],
        database=opds_system_db["database"],
        host=opds_system_db["address"],
        port=opds_system_db["port"]
    )
    sql = f'SELECT `id`, user_code FROM tb_user WHERE email="{user_email}"'  # 대상 파일 선택
    cs = opds_sysdb_conn.cursor()
    cs.execute(sql)
    rs = cs.fetchall()
    user_name_df = pd.DataFrame(rs, columns=['id', 'user_code'])
    cs.close()
    opds_sysdb_conn.close()

    if user_name_df.shape[0] == 1:
        user_name_df = user_name_df.iloc[0].to_dict()
        ucode = user_name_df["user_code"]
        return  ucode

for dummpy in dummy_list:
    user_email = dummpy["user_email"]
    file_name = dummpy["file_name"]

    user_code = get_usercode_fromid(user_email)
    stat = client.stat_object(user_code, file_name)
    object_size= stat.size

    user_id = get_userid_fromcode(user_code)
    doc_id = insert_fileinfo(user_id, file_name, object_size)[0]
    prep_msg = json.dumps(  {"user_email": user_email,
                            "user_code": user_code,
                            "doc_id": doc_id,
                            "file_name":file_name})
    print(json.loads(prep_msg))
    OPDS_RREP.basic_publish(exchange=OPDS_RREP_REQ_Ex, routing_key=OPDS_RREP_ROUTE, body=prep_msg)
