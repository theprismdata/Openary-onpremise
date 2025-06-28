@echo off
REM "Build the Docker image"
docker build -t 222.239.231.95:30010/incen-demo/incen-nginx:0.0.1 .

REM "Login to Harbor registry"
docker login 222.239.231.95:30010 -u incen -p EntecIncen2025!

REM "Push to Harbor registry"
docker push 222.239.231.95:30010/incen-demo/incen-nginx:0.0.1