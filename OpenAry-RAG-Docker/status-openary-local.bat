@echo off
chcp 65001 > nul
echo ========================================
echo OpenAry Local Environment Status Check
echo ========================================
echo.

REM openary-local-compose.yaml 파일 존재 확인
if not exist "openary-local-compose.yaml" (
    echo [ERROR] openary-local-compose.yaml 파일을 찾을 수 없습니다.
    echo [ERROR] 현재 디렉토리에 openary-local-compose.yaml 파일이 있는지 확인하세요.
    echo.
    pause
    exit /b 1
)

echo [INFO] OpenAry 서비스 상태 확인 중...
echo.

docker-compose -f openary-local-compose.yaml ps

echo.
echo ========================================
echo 서비스 접속 정보:
echo ========================================
echo - NGINX (웹): http://localhost
echo - Chat API: http://localhost:9000
echo - Management: http://localhost:9001
echo - Ollama LLM: http://localhost:11434
echo - Redis: localhost:6379
echo - RabbitMQ Management: http://localhost:15672 (opds/opds_pass)
echo - MinIO Console: http://localhost:9001 (opds/opds_pass)
echo - MariaDB: localhost:3306 (genai/openary)
echo - PostgreSQL: localhost:5432 (genai/openary)
echo - MongoDB: localhost:27017 (genai/openary)
echo.
echo ========================================
echo 유용한 명령어:
echo ========================================
echo 전체 로그 확인: docker-compose -f openary-local-compose.yaml logs -f
echo 특정 서비스 로그: docker-compose -f openary-local-compose.yaml logs -f [서비스명]
echo 서비스 재시작: docker-compose -f openary-local-compose.yaml restart [서비스명]
echo 서비스 중지: docker-compose -f openary-local-compose.yaml down
echo.

pause 