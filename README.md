#LLM-RAG Onpremise
## OpenAry RAG Docker
### 로컬 컴퓨터에서 동작하도록 Docker 기반 스토리지를 설정합니다.

## OpenAry RAG API Server
### OPenDocuSea Embedding
### Mongodb에 저장된 text 데이터를 gpt를 이용하여 행렬로 변환하여 pgvector저장한다.
##### Step 1 RabbitMQ의 Qeueue이름  OPDS_EMBEDDING_REQ 메시지를 수신 받는다.
##### Step 2 메시지에는 user_code, 문서 번호, 문서 파일명이 설정되어 있다.
##### Step 3 행렬 데이터를 pgvector의 user_code 테이블에 저장한다.

### OPenDocuSea Preprocess
#### 파일로 부터 문서의 내용을 추출하여 text로 변환 후 mongodb에 저장
##### Step 1 RabbitMQ의 Qeueue이름  OPDS_PREP_REQ에서 메시지를 수신 받는다.
##### Step 2 메시지에는 user_email, 문서 번호, 문서 파일명이 설정되어 있다.
##### Step 3 user_email을 user_code로 변환하여 user_code 버컷에 저장된 문서를 열어 전처리를 수행하여 mongodb에 저장한다.

### OPenDocuSea Summary
#### Mongodb에 저장된 text 데이터를 gpt를 이용하여 요약을 수행함.
##### Step 1 RabbitMQ의 Qeueue이름  OPDS_SUMMARY_REQ 메시지를 수신 받는다.
##### Step 2 메시지에는 user_code, 문서 번호, 문서 파일명이 설정되어 있다.
######## Step 3 text를 gpt를 이용하여 요약을 수행하고, Mariadb에 등록한다.


### Maintainer
프론트	tnrud4685@gmail.com 이수경 <br>
RAG, BACKEND	theprismdata@gmail.com 신홍중 <br>
CA	armyost1@gmail.com 김종표 <br>
기획/설계	ljs9643@gmail.com 이재수<br>