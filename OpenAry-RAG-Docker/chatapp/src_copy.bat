@echo off
rem chatapp_src 폴더가 없으면 생성
if not exist chatapp_src mkdir chatapp_src

rem nginx 폴더의 파일들 복사
copy nginx\nginx.conf chatapp_src\

rem src 폴더의 js, jsx 파일들 복사
for /r "src" %%f in (*.js) do (
    echo %%~nxf | findstr /i "chatSlice.jsx" > nul
    if errorlevel 1 copy "%%f" chatapp_src\
)
for /r "src" %%f in (*.js) do (
    echo %%~nxf | findstr /i "sessionStorage.js" > nul
    if errorlevel 1 copy "%%f" chatapp_src\
)
for /r "src" %%f in (*.js) do (
    echo %%~nxf | findstr /i "store.js" > nul
    if errorlevel 1 copy "%%f" chatapp_src\
)
for /r "src" %%f in (*.jsx) do (
    echo %%~nxf | findstr /i "chatSlice.jsx" > nul
    if errorlevel 1 copy "%%f" chatapp_src\
)
for /r "src" %%f in (*.jsx) do (
    echo %%~nxf | findstr /i "authSlice.jsx" > nul
    if errorlevel 1 copy "%%f" chatapp_src\
)
for /r "src" %%f in (*.jsx) do (
    echo %%~nxf | findstr /i "ProtectedRoute.jsx" > nul
    if errorlevel 1 copy "%%f" chatapp_src\
)
for /r "src" %%f in (*.jsx) do (
    echo %%~nxf | findstr /i "MessageInput.jsx" > nul
    if errorlevel 1 copy "%%f" chatapp_src\
)


rem chatapp 폴더의 json 파일과 dockerfile 복사
copy package.json chatapp_src\
copy vite.config.js chatapp_src\
copy Dockerfile chatapp_src\