# OpenAry RAG 설정

이 디렉토리는 OpenAry RAG 시스템의 설정 파일을 포함합니다.

## 설정 파일

### svc-set.yaml

모든 서비스 설정을 포함하는 메인 설정 파일입니다.

#### 필수 설정 단계

1. **샘플 설정 파일 복사:**
   
   **Windows (PowerShell):**
   ```powershell
   Copy-Item config\svc-set.yaml config\svc-set.local.yaml
   ```
   
   **macOS/Linux (Terminal):**
   ```bash
   cp config/svc-set.yaml config/svc-set.local.yaml
   ```

2. **API 키 업데이트:**
   설정 파일을 텍스트 에디터로 열어서 플레이스홀더 값을 실제 API 키로 교체하세요:
   
   **Windows:**
   ```powershell
   notepad config\svc-set.local.yaml
   ```
   
   **macOS:**
   ```bash
   open -e config/svc-set.local.yaml
   # 또는 VS Code가 설치되어 있다면:
   code config/svc-set.local.yaml
   ```
   
   교체할 API 키들:
   - `your-openai-api-key-here` - OpenAI API 키
   - `your-claude-api-key-here` - Anthropic Claude API 키
   - `your-huggingface-api-key-here` - Hugging Face API 키
   - `your-serper-api-key-here` - 웹 검색용 Serper API 키
   - `your-tavily-api-key-here` - 웹 검색용 Tavily API 키
   - `your-upstage-api-key-here` - Upstage API 키

3. **시크릿 키 생성:**
   
   **Windows (PowerShell):**
   ```powershell
   # SECRET_KEY 생성
   [System.Web.Security.Membership]::GeneratePassword(64, 0)
   
   # 또는 Python이 설치되어 있다면:
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
   
   **macOS/Linux (Terminal):**
   ```bash
   # Python 사용
   python3 -c "import secrets; print(secrets.token_hex(32))"
   
   # 또는 OpenSSL 사용
   openssl rand -hex 32
   
   # 또는 온라인 생성기 사용:
   # https://www.allkeysgenerator.com/Random/Security-Encryption-Key-Generator.aspx
   ```

4. **언어 모델 설정:**
   - 외부 API(OpenAI, Claude 등)를 사용하려면 `RUN_MODE`를 `API`로 설정
   - 로컬 Ollama 모델을 사용하려면 `RUN_MODE`를 `LOCAL`로 설정
   - 로컬 모드 사용 시 Ollama에서 필요한 모델을 미리 다운로드해야 합니다

#### 서비스 엔드포인트 (Docker 환경)

모든 서비스 엔드포인트는 Docker Compose 환경에 맞게 미리 설정되어 있습니다:

- **MinIO**: `opds-minio:9000`
- **Redis**: `redis-stack:6379`
- **PostgreSQL (pgvector)**: `pgvector:5432`
- **OpenSearch**: `opensearch:9200`
- **Qdrant**: `qdrant:6333`
- **MariaDB**: `mariadb:3306`
- **MongoDB**: `mongodb:27017`
- **RabbitMQ**: `opds-rabbit-mq:5672`

#### 데이터베이스 설정

시스템은 다음과 같은 다중 벡터 데이터베이스를 지원합니다:

1. **PostgreSQL with pgvector** - 벡터 유사도 검색용
2. **OpenSearch** - 전문 검색 및 벡터 검색용
3. **Qdrant** - 전용 벡터 데이터베이스
4. **MariaDB** - 시스템 메타데이터 및 사용자 관리
5. **MongoDB** - 채팅 히스토리 및 문서 메타데이터

#### 보안 주의사항

- 실제 API 키를 버전 관리 시스템에 커밋하지 마세요
- 프로덕션 환경에서는 환경 변수나 별도 설정 파일을 사용하세요
- API 키와 시크릿 키를 정기적으로 교체하세요
- 프로덕션 환경에서는 민감한 정보에 대해 Docker secrets 사용을 고려하세요

#### 환경 변수 오버라이드

**Windows (PowerShell):**
```powershell
# 현재 세션에서만 설정
$env:OPDS_LANGMODEL_API_OPENAI_APIKEY = "실제-openai-키"
$env:OPDS_SECRET_KEY = "실제-시크릿-키"

# 영구적으로 설정 (사용자 레벨)
[Environment]::SetEnvironmentVariable("OPDS_LANGMODEL_API_OPENAI_APIKEY", "실제-openai-키", "User")
[Environment]::SetEnvironmentVariable("OPDS_SECRET_KEY", "실제-시크릿-키", "User")
```

**macOS/Linux (Terminal):**
```bash
# 현재 세션에서만 설정
export OPDS_LANGMODEL_API_OPENAI_APIKEY="실제-openai-키"
export OPDS_SECRET_KEY="실제-시크릿-키"

# 영구적으로 설정 (bash)
echo 'export OPDS_LANGMODEL_API_OPENAI_APIKEY="실제-openai-키"' >> ~/.bashrc
echo 'export OPDS_SECRET_KEY="실제-시크릿-키"' >> ~/.bashrc

# 영구적으로 설정 (zsh - macOS 기본)
echo 'export OPDS_LANGMODEL_API_OPENAI_APIKEY="실제-openai-키"' >> ~/.zshrc
echo 'export OPDS_SECRET_KEY="실제-시크릿-키"' >> ~/.zshrc
```

#### 시작하기

### Windows 사용자

1. **Docker Desktop 설치 확인:**
   ```powershell
   docker --version
   docker-compose --version
   ```

2. **설정 파일 복사 및 수정:**
   ```powershell
   Copy-Item config\svc-set.yaml config\svc-set.local.yaml
   notepad config\svc-set.local.yaml
   ```

3. **필요한 디렉토리 생성:**
   ```powershell
   New-Item -ItemType Directory -Force -Path C:\temp\ollama_data
   New-Item -ItemType Directory -Force -Path C:\temp\rabbitmq_data
   New-Item -ItemType Directory -Force -Path C:\temp\minio_data
   New-Item -ItemType Directory -Force -Path C:\temp\mariadb_data
   New-Item -ItemType Directory -Force -Path C:\temp\pgdata
   New-Item -ItemType Directory -Force -Path C:\temp\mongodb_data
   New-Item -ItemType Directory -Force -Path C:\temp\qdrant_data
   New-Item -ItemType Directory -Force -Path C:\temp\opensearch_data
   ```

4. **타임존 파일 생성 (선택사항):**
   ```powershell
   New-Item -ItemType File -Force -Path C:\temp\timezone
   ```

5. **Docker Compose 실행:**
   ```powershell
   docker-compose -f openary-local-compose.yaml up -d
   ```

### macOS 사용자

1. **Docker Desktop 설치 확인:**
   ```bash
   docker --version
   docker-compose --version
   ```

2. **설정 파일 복사 및 수정:**
   ```bash
   cp config/svc-set.yaml config/svc-set.local.yaml
   open -e config/svc-set.local.yaml
   ```

3. **필요한 디렉토리 생성:**
   ```bash
   mkdir -p ~/docker-volumes/openary/{ollama_data,rabbitmq_data,minio_data,mariadb_data,pgdata,mongodb_data,qdrant_data,opensearch_data}
   ```

4. **Docker Compose 파일 수정 (macOS용 경로):**
   `openary-local-compose.yaml` 파일에서 볼륨 경로를 다음과 같이 수정:
   ```yaml
   # Windows 경로: C:/temp/ollama_data:/root/.ollama
   # macOS 경로로 변경:
   volumes:
     - ~/docker-volumes/openary/ollama_data:/root/.ollama
     - ~/docker-volumes/openary/rabbitmq_data:/var/lib/rabbitmq
     - ~/docker-volumes/openary/minio_data:/data
     # ... 다른 볼륨들도 동일하게 변경
   ```

5. **Docker Compose 실행:**
   ```bash
   docker-compose -f openary-local-compose.yaml up -d
   ```

### 공통 명령어

**서비스 상태 확인:**
```bash
docker-compose -f openary-local-compose.yaml ps
```

**로그 확인:**
```bash
# 모든 서비스 로그
docker-compose -f openary-local-compose.yaml logs -f

# 특정 서비스 로그
docker-compose -f openary-local-compose.yaml logs -f opds-chatapi
```

**서비스 중지:**
```bash
docker-compose -f openary-local-compose.yaml down
```

#### 서비스 접속 URL

- **웹 인터페이스**: http://localhost
- **Chat API 서버**: http://localhost:9000
- **관리 서버**: http://localhost:9001
- **MinIO 콘솔**: http://localhost:9011
- **RabbitMQ 관리**: http://localhost:15672
- **OpenSearch 대시보드**: http://localhost:5601
- **Ollama API**: http://localhost:11434

#### 문제 해결

### Windows

**Docker Desktop이 시작되지 않는 경우:**
```powershell
# Docker Desktop 서비스 재시작
Restart-Service -Name "com.docker.service"
```

**포트 충돌이 발생하는 경우:**
```powershell
# 사용 중인 포트 확인
netstat -ano | findstr :80
netstat -ano | findstr :9000
```

**볼륨 권한 문제가 발생하는 경우:**
- Docker Desktop 설정에서 C:\ 드라이브 공유를 활성화하세요
- 또는 WSL2 백엔드를 사용하세요

### macOS

**Docker Desktop이 시작되지 않는 경우:**
```bash
# Docker Desktop 재시작
killall Docker && open /Applications/Docker.app
```

**포트 충돌이 발생하는 경우:**
```bash
# 사용 중인 포트 확인
lsof -i :80
lsof -i :9000

# 특정 포트를 사용하는 프로세스 종료
sudo kill -9 $(lsof -ti:80)
```

**볼륨 권한 문제가 발생하는 경우:**
```bash
# 볼륨 디렉토리 권한 설정
chmod -R 755 ~/docker-volumes/openary/
```

**M1/M2 Mac에서 이미지 호환성 문제:**
```bash
# ARM64 호환 이미지 사용 또는 Rosetta 에뮬레이션
docker-compose -f openary-local-compose.yaml up -d --platform linux/amd64
``` 