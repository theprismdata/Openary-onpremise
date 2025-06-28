FROM nginx:alpine

# Nginx 설정 파일 복사
COPY ./k8s-nginx.conf /etc/nginx/nginx.conf
COPY ./mime.types /etc/nginx/mime.types

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]