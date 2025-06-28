echo "Build the Docker image"
docker build -t 222.239.231.95:30010/incen-demo/incen-nginx:0.0.1 .

echo "Login to Harbor registry"
docker login 222.239.231.95:30010 -u incen -p EntecIncen2025!

echo "Push to Harbor registry"
docker push 222.239.231.95:30010/incen-demo/incen-nginx:0.0.1