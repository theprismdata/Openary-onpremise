@echo off
chcp 65001 > nul
echo ========================================
echo OpenAry Local Environment Setup Script
echo ========================================
echo.

REM 관리자 권한 확인
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] 관리자 권한으로 실행하는 것을 권장합니다.
    echo [WARNING] 일부 디렉토리 생성이 실패할 수 있습니다.
    echo.
    pause
)

echo [INFO] C:\temp 디렉토리 구조 생성 중...

REM 기본 temp 디렉토리 생성
if not exist "C:\temp" (
    mkdir "C:\temp"
    echo [OK] C:\temp 디렉토리 생성됨
) else (
    echo [OK] C:\temp 디렉토리 이미 존재
)

REM 데이터 디렉토리들 생성
set directories=ollama_data rabbitmq_data minio_data mariadb_data pgdata mongodb_data

for %%d in (%directories%) do (
    if not exist "C:\temp\%%d" (
        mkdir "C:\temp\%%d"
        echo [OK] C:\temp\%%d 디렉토리 생성됨
    ) else (
        echo [OK] C:\temp\%%d 디렉토리 이미 존재
    )
)

REM 타임존 파일 생성
if not exist "C:\temp\timezone" (
    echo. > "C:\temp\timezone"
    echo [OK] C:\temp\timezone 파일 생성됨
) else (
    echo [OK] C:\temp\timezone 파일 이미 존재
)

echo.
echo [INFO] 디렉토리 구조 생성 완료!
echo.

REM Docker 설치 확인
docker --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Docker가 설치되지 않았거나 실행되지 않습니다.
    echo [ERROR] Docker Desktop을 설치하고 실행한 후 다시 시도하세요.
    echo.
    pause
    exit /b 1
)

REM Docker Compose 설치 확인
docker-compose --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Docker Compose가 설치되지 않았습니다.
    echo [ERROR] Docker Desktop을 최신 버전으로 업데이트하세요.
    echo.
    pause
    exit /b 1
)

echo [OK] Docker 및 Docker Compose 확인됨
echo.

REM openary-local-compose.yaml 파일 존재 확인
if not exist "openary-local-compose.yaml" (
    echo [ERROR] openary-local-compose.yaml 파일을 찾을 수 없습니다.
    echo [ERROR] 현재 디렉토리에 openary-local-compose.yaml 파일이 있는지 확인하세요.
    echo.
    pause
    exit /b 1
)

echo [OK] openary-local-compose.yaml 파일 확인됨
echo.

REM 사용자에게 실행 여부 확인
echo ========================================
echo 다음 작업을 수행합니다:
echo 1. 기존 컨테이너 중지 및 제거
echo 2. OpenAry 서비스 컨테이너 시작
echo ========================================
echo.
set /p choice="계속하시겠습니까? (Y/N): "
if /i "%choice%" neq "Y" (
    echo [INFO] 사용자에 의해 취소되었습니다.
    pause
    exit /b 0
)

echo.
echo [INFO] 기존 컨테이너 중지 및 제거 중...
docker-compose -f openary-local-compose.yaml down

echo.
echo [INFO] OpenAry 서비스 시작 중...
docker-compose -f openary-local-compose.yaml up -d

if %errorLevel% equ 0 (
    echo.
    echo ========================================
    echo [SUCCESS] OpenAry 로컬 환경이 성공적으로 시작되었습니다!
    echo ========================================
    echo.
    echo 서비스 접속 정보:
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
    echo 컨테이너 상태 확인: docker-compose -f openary-local-compose.yaml ps
    echo 로그 확인: docker-compose -f openary-local-compose.yaml logs -f [서비스명]
    echo 서비스 중지: docker-compose -f openary-local-compose.yaml down
    echo.
) else (
    echo.
    echo [ERROR] 서비스 시작 중 오류가 발생했습니다.
    echo [ERROR] 로그를 확인하세요: docker-compose -f openary-local-compose.yaml logs
    echo.
)

pause 