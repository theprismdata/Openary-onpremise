#!/usr/bin/env python
# coding: utf-8

# In[69]:


#LLM_DOC와 File Sync
import yaml
import pandas as pd
import os
import pymysql
# from pymilvus import connections as milvus_conn
# from pymilvus import utility
# from pymilvus import Collection
import pymongo
import time

import os
import logging
from logging.handlers import TimedRotatingFileHandler
if not os.path.exists("../log"):
    os.makedirs("../log")

logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)

f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
path = "./log/tablefilesync.log"
handler = TimedRotatingFileHandler(path,
                                   when="h",
                                   interval=1,
                                   backupCount=24)
handler.namer = lambda name: name + ".txt"
handler.setFormatter(f_format)
logger.addHandler(handler)


with open('../config/set_dev.yaml') as f:
    config = yaml.load(f, Loader=yaml.FullLoader)

OPENAI_API_KEY = config['openai']['apikey']
OPENAI_EMBEDDING_MODEL = config['openai']['embedding_model']

milvus_vector_db_address = config['database']['vector_db']['address']
milvus_vector_db_port = config['database']['vector_db']['port']
milvus_vector_db = config['database']['vector_db']['db']
mariadb_info = config['database']['llm_db']
upload_path = config['upload_path']
mongo_host = config['database']['mongodb']['mongo_host']
mongo_port = config['database']['mongodb']['mongo_port']
mongo_user = config['database']['mongodb']['mongo_user']
mongo_passwd = config['database']['mongodb']['mongo_passwd']
auth_source = config['database']['mongodb']['auth_source']

while True:
  mariadb_conn = pymysql.connect(
          user=mariadb_info["id"],
          password=mariadb_info["pwd"],
          database=mariadb_info["database"],
          host=mariadb_info["address"],
          port=mariadb_info["port"]
      )
  
  get_delete_row_sql = f"SELECT `id`, userid, filename FROM tb_llm_doc where status='delete'"  # 삭제 대상 선택
  cs = mariadb_conn.cursor()
  cs.execute(get_delete_row_sql)
  rs = cs.fetchall()
  user_df = pd.DataFrame(rs, columns=['id', 'userid', 'filename'])
  cs.close()
  
  mongo_uri = f"mongodb://{mongo_user}:{mongo_passwd}@{mongo_host}:{mongo_port}/?authSource={auth_source}&authMechanism=SCRAM-SHA-1"
  mongo_client = pymongo.MongoClient(mongo_uri)
  mongo_genai = mongo_client[auth_source]
  
  for row in user_df.iterrows():
      rdb_row_id = row[1]['id']
      rdb_user_id = row[1]['userid']
      rdb_file_path = row[1]['filename']
      print('remove target', rdb_row_id, rdb_user_id, rdb_file_path)
      logger.info(f'remove target {rdb_row_id}, {rdb_user_id}, {rdb_file_path}')

      #remove from tb_llm_doc by userid and id
      del_row_row_id_sql = f"DELETE FROM tb_llm_doc WHERE id = {rdb_row_id} and userid = '{rdb_user_id}'"
      cs = mariadb_conn.cursor()
      cs.execute(del_row_row_id_sql)
      cs.close()
      mariadb_conn.commit()
  
      #remove from milvus entity by user id
      # milvus_conn.connect(host=milvus_vector_db_address, port=milvus_vector_db_port, db_name=milvus_vector_db)
      # collection = Collection(rdb_user_id)
      #
      # mil_file_path = os.path.join(upload_path, rdb_file_path)
      # expr_value = f'source == "{mil_file_path}"'
      # # print('milvus delete entities', mil_file_path)
      # logger.info(f'milvus delete entities {mil_file_path}')
      # collection.delete(expr=expr_value)
  
      #remove mongodb collection by id
      mongo_del_doc_query = {"id":rdb_row_id}
      rtn = mongo_genai[rdb_user_id].delete_one(mongo_del_doc_query)
      #print('mongo delete document', rdb_user_id, 'id', rdb_row_id)
      logger.info(f'mongo delete document {rdb_user_id} id {rdb_row_id}')
      srtn = str(rtn)
      logger.info(f'mongo delete result {srtn}')
      try:
          os.remove(mil_file_path)
          logger.info(f'file system file remove success {mil_file_path}')
      except OSError:
          pass
      
  mariadb_conn.close()
  time.sleep(1)


# In[ ]:





# In[ ]:




