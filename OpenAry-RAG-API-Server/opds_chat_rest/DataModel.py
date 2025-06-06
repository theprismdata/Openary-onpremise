from typing import List

from pydantic import BaseModel, Field
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, and_, text

Base = declarative_base()
class User(Base):
    __tablename__ = "tb_user"
    id = Column(Integer, primary_key=True, index=True)
    user_code = Column(String(200))
    email = Column(String(200))
    password = Column(String(512))

class DocFile(Base):
    __tablename__ = "tb_llm_doc"
    id = Column(Integer, primary_key=True, index=True)
    userid = Column(String(200))
    filename = Column(String(200))
    summary = Column(String(512))
    extract_page_rate = Column(Integer)
    embedding_rate = Column(Integer)

class UserCreate(BaseModel):
    email: str
    password: str # 해시전 패스워드를 받습니다.

class UserInfo(BaseModel):
    email: str = Field(default="guest@openary.io")
    password: str = Field(default="guest")

class ChatRQA(BaseModel):
    email: str = Field(default="guest@openary.io")
    question: str = Field(default="청년 주택 정보를 찾아줘")
    session_id: int
    isnewsession: bool = Field(default=True)

class DropDocsInfo(BaseModel):
    email: str = Field(default="guest@openary.io")
    files: List[str]

class EmailSession(BaseModel):
    email: str = Field(default="guest@openary.io")
    session: int

class EmailInfo(BaseModel):
    email: str = Field(default="guest@openary.io")