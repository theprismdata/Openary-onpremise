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

if not os.path.exists("log"):
    os.makedirs("log")
logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)

f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
path = "./log/opds_mgmt_user.log"
handler = TimedRotatingFileHandler(path,
                                   when="h",
                                   interval=1,
                                   backupCount=24)
handler.namer = lambda name: name + ".txt"
handler.setFormatter(f_format)
logger.addHandler(handler)

# Pycharm에서 수행시.
# module : flask
# run
# NUNBUFFERED=1;FLASK_APP=opds_mgmt_user.py;FLASK_ENV=dev

with open('../config/svc-set.yaml') as f:
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
opds_system_db = config['database']['opds_system_db']

mongo_host = config['database']['mongodb']['mongo_host']
mongo_port = config['database']['mongodb']['mongo_port']
mongo_user = config['database']['mongodb']['mongo_user']
mongo_passwd = config['database']['mongodb']['mongo_passwd']
auth_source = config['database']['mongodb']['auth_source']

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
        user remove from mariadb, minio, pgvector
        :param email:

        :return:
        """
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
            mail_sha_code = make_sha_email(email)
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
            # VectorDB
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
            return 0, "ok" #정상 추가됨.
        elif auth_status == -1: #암호 오류 (사용자가 존재하는데 다시 모르고 가입하려는 경우)
            return -1, "Auth Fail"
        elif auth_status == 0: # 사용자 존재함.
            return 1, "User exist"
        elif auth_status == -2: # email DB 검증 오류
            return -2, f"DB Error {msg}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=rest_config['port'], debug=False)