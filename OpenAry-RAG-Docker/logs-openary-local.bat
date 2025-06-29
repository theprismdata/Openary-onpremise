@echo off
chcp 65001 > nul
echo ========================================
echo OpenAry Local Environment Logs Viewer
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

echo 로그를 확인할 서비스를 선택하세요:
echo.
echo 1. 전체 서비스 로그
echo 2. opds-nginx
echo 3. opds-chatapi
echo 4. opds-mgmt
echo 5. opds-embedding (모든 인스턴스)
echo 6. opds-preprocess (모든 인스턴스)
echo 7. opds-summary
echo 8. ollama
echo 9. redis-stack
echo 10. opds-rabbit-mq
echo 11. opds-minio
echo 12. mariadb
echo 13. postgres
echo 14. mongodb
echo.

set /p choice="선택 (1-14): "

if "%choice%"=="1" (
    echo [INFO] 전체 서비스 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f
) else if "%choice%"=="2" (
    echo [INFO] opds-nginx 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f opds-nginx
) else if "%choice%"=="3" (
    echo [INFO] opds-chatapi 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f opds-chatapi
) else if "%choice%"=="4" (
    echo [INFO] opds-mgmt 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f opds-mgmt
) else if "%choice%"=="5" (
    echo [INFO] opds-embedding (모든 인스턴스) 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f opds-embedding-1 opds-embedding-2 opds-embedding-3
) else if "%choice%"=="6" (
    echo [INFO] opds-preprocess (모든 인스턴스) 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f opds-preprocess-1 opds-preprocess-2 opds-preprocess-3
) else if "%choice%"=="7" (
    echo [INFO] opds-summary 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f opds-summary
) else if "%choice%"=="8" (
    echo [INFO] ollama 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f ollama
) else if "%choice%"=="9" (
    echo [INFO] redis-stack 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f redis-stack
) else if "%choice%"=="10" (
    echo [INFO] opds-rabbit-mq 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f opds-rabbit-mq
) else if "%choice%"=="11" (
    echo [INFO] opds-minio 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f opds-minio
) else if "%choice%"=="12" (
    echo [INFO] mariadb 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f mariadb
) else if "%choice%"=="13" (
    echo [INFO] postgres 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f postgres
) else if "%choice%"=="14" (
    echo [INFO] mongodb 로그를 확인합니다...
    docker-compose -f openary-local-compose.yaml logs -f mongodb
) else (
    echo [ERROR] 잘못된 선택입니다.
    pause
    exit /b 1
)

echo.
echo [INFO] 로그 보기를 종료하려면 Ctrl+C를 누르세요.
echo. 