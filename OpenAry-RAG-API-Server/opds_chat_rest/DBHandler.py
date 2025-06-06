import logging
from logging.handlers import TimedRotatingFileHandler

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import QueuePool
from contextlib import contextmanager
import os


class DatabaseConnectionManager:
    def __init__(self, logger, database_url, pool_size=5, max_overflow=10, pool_timeout=30):
        self.logger = logger
        self.engine = create_engine(
            database_url,
            poolclass=QueuePool,
            pool_size=pool_size,  # 기본 풀 크기
            max_overflow=max_overflow,  # 추가로 생성 가능한 최대 연결 수
            pool_timeout=pool_timeout,  # 연결 대기 시간
            pool_pre_ping=True,  # 연결 유효성 검사
            pool_recycle=3600,  # 연결 재활용 시간 (1시간)
        )

        # 세션 팩토리 생성
        session_factory = sessionmaker(bind=self.engine)
        self.Session = scoped_session(session_factory)

    @contextmanager
    def get_session(self):
        """
        데이터베이스 세션을 컨텍스트 매니저로 제공
        자동으로 세션을 닫고 예외 처리를 수행
        """
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            self.logger.error(f"Database error: {str(e)}")
        finally:
            session.close()
            self.Session.remove()

    def check_connection(self):
        """
        데이터베이스 연결 상태 확인
        """
        try:
            with self.get_session() as session:
                session.execute("SELECT 1")
            return True
        except Exception as e:
            self.logger.error(f"Connection check failed: {str(e)}")
            return False

    def get_pool_status(self):
        """
        현재 커넥션 풀 상태 반환
        """
        return {
            'pool_size': self.engine.pool.size(),
            'checkedin': self.engine.pool.checkedin(),
            'checkedout': self.engine.pool.checkedout(),
            'overflow': self.engine.pool.overflow()
        }