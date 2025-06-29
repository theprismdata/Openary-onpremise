@echo off
chcp 65001 > nul
echo ========================================
echo OpenAry Local Environment Cleanup Script
echo ========================================
echo.

REM 관리자 권한 확인
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] 관리자 권한으로 실행하는 것을 권장합니다.
    echo [WARNING] 일부 파일 삭제가 실패할 수 있습니다.
    echo.
    pause
)

echo [WARNING] 이 스크립트는 다음 작업을 수행합니다:
echo 1. 모든 OpenAry 컨테이너 중지 및 제거
echo 2. C:\temp 디렉토리의 모든 데이터 삭제
echo 3. Docker 볼륨 및 네트워크 정리
echo.
echo [CAUTION] 이 작업은 되돌릴 수 없습니다!
echo [CAUTION] 모든 데이터베이스 데이터와 설정이 삭제됩니다!
echo.

set /p choice="정말로 계속하시겠습니까? (YES/NO): "
if /i "%choice%" neq "YES" (
    echo [INFO] 사용자에 의해 취소되었습니다.
    pause
    exit /b 0
)

echo.
echo [INFO] OpenAry 서비스 중지 및 컨테이너 제거 중...

REM openary-local-compose.yaml 파일이 있으면 서비스 중지
if exist "openary-local-compose.yaml" (
    docker-compose -f openary-local-compose.yaml down -v
) else (
    echo [WARNING] openary-local-compose.yaml 파일을 찾을 수 없습니다.
)

echo.
echo [INFO] C:\temp 디렉토리 데이터 삭제 중...

REM 데이터 디렉토리들 삭제
set directories=ollama_data rabbitmq_data minio_data mariadb_data pgdata mongodb_data

for %%d in (%directories%) do (
    if exist "C:\temp\%%d" (
        echo [INFO] C:\temp\%%d 삭제 중...
        rmdir /s /q "C:\temp\%%d"
        if exist "C:\temp\%%d" (
            echo [ERROR] C:\temp\%%d 삭제 실패
        ) else (
            echo [OK] C:\temp\%%d 삭제됨
        )
    ) else (
        echo [INFO] C:\temp\%%d 디렉토리가 존재하지 않음
    )
)

REM 타임존 파일 삭제
if exist "C:\temp\timezone" (
    del "C:\temp\timezone"
    echo [OK] C:\temp\timezone 파일 삭제됨
) else (
    echo [INFO] C:\temp\timezone 파일이 존재하지 않음
)

echo.
echo [INFO] Docker 시스템 정리 중...

REM 사용하지 않는 Docker 리소스 정리
docker system prune -f

REM OpenAry 관련 이미지 확인
echo.
echo [INFO] OpenAry 관련 Docker 이미지:
docker images | findstr hongjoong

echo.
set /p remove_images="OpenAry 이미지도 삭제하시겠습니까? (Y/N): "
if /i "%remove_images%"=="Y" (
    echo [INFO] OpenAry 이미지 삭제 중...
    for /f "tokens=1" %%i in ('docker images --format "{{.Repository}}:{{.Tag}}" ^| findstr hongjoong') do (
        echo [INFO] %%i 삭제 중...
        docker rmi %%i
    )
)

echo.
echo ========================================
echo [SUCCESS] 정리 작업이 완료되었습니다!
echo ========================================
echo.
echo 정리된 항목:
echo - OpenAry 컨테이너 및 볼륨
echo - C:\temp 데이터 디렉토리
echo - 사용하지 않는 Docker 리소스
if /i "%remove_images%"=="Y" (
    echo - OpenAry Docker 이미지
)
echo.
echo 새로 시작하려면 setup-openary-local.bat을 실행하세요.
echo.

pause 