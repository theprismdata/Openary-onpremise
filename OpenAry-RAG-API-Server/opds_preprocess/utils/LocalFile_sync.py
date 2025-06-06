#!/usr/bin/env python
# coding: utf-8

import os
import platform

import yaml
from datetime import datetime
import pymysql
from pytz import timezone
import pandas as pd

with open('../config/set_dev.yaml') as f:
    config = yaml.load(f, Loader=yaml.FullLoader)
mariadb_info = config['database']['llm_db']
mariadb_conn = pymysql.connect(
        user=mariadb_info["id"],
        password=mariadb_info["pwd"],
        database=mariadb_info["database"],
        host=mariadb_info["address"],
        port=mariadb_info["port"]
    )

def listup_files(initdir: str, file_extensions: list):
    '''
    Returns a list of file under initdir and all its subdirectories
    that have file extension contained in file_extensions.
    '''
    file_list = []
    file_count = {key: 0 for key in file_extensions}  # for reporting only

    # Traverse through directories to find files with specified extensions
    for root, _, files in os.walk(initdir):
        for file in files:
            ext = file.split('.')[-1].lower()
            if ext in file_extensions:
                file_path = os.path.join(root, file)
                file_list.append(file_path)
                file_count[ext] += 1
    total = len(file_list)
    print(f'There are {total} files under dir {initdir}.')
    for k, n in file_count.items():
        print(f'   {n} : ".{k}" files')
    return file_list

file_extensions = ['pdf', 'doc', 'docx', 'xlsx', 'xls', 'ppt', 'pptx', 'txt', 'csv', 'hwp']
userid = "guest_003"
windows_base_dir = "D:\\1.Developing\\GenAI_PersonalProjecet\\upload\\" #윈도우에 저장된 문서 경로

initdir = os.path.join(windows_base_dir, userid)

filelst = listup_files(initdir, file_extensions)

for filename in filelst:
    print(filename)
    filesize = os.path.getsize(filename)
    filename = filename.replace(windows_base_dir, "")
    if platform.system() == 'Windows':
        filename = filename.replace("\\", "/")
    sql = f'SELECT userid FROM {mariadb_info["database"]}.tb_llm_doc where  userid="{userid}" and filename="{filename}"'
    cs = mariadb_conn.cursor()
    cs.execute(sql)
    rs = cs.fetchall()
    user_df = pd.DataFrame(rs, columns=['userid'])
    cs.close()
    if user_df.shape[0] == 0:
        sql = f"""INSERT INTO {mariadb_info["database"]}.tb_llm_doc (filename, filesize, status, uploaded, userid) 
                    values (%s, %s, %s, %s, %s)"""
        cs = mariadb_conn.cursor()
        status = 'upload'
        uploaded = datetime.now(timezone('Asia/Seoul')).strftime("%Y-%m-%d %H:%M:%S.%f")
        cs.execute(sql, (filename, filesize, status, uploaded, userid))
mariadb_conn.close()


