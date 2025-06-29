@echo off
chcp 65001 > nul
echo ========================================
echo OpenAry Local Environment Stop Script
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

echo [INFO] OpenAry 서비스 중지 중...
docker-compose -f openary-local-compose.yaml down

if %errorLevel% equ 0 (
    echo.
    echo [SUCCESS] OpenAry 서비스가 성공적으로 중지되었습니다.
    echo.
) else (
    echo.
    echo [ERROR] 서비스 중지 중 오류가 발생했습니다.
    echo.
)

pause 