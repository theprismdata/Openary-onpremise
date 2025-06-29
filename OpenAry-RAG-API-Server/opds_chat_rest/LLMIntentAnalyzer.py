import json
import re
from langchain_core.messages import HumanMessage

class LLMIntentAnalyzer:
    """LLM을 활용하여 사용자 질문의 의도를 분석하는 강화된 클래스"""

    def __init__(self, logger, llm_selector):
        """
        Args:
            llm_selector: LLM 선택자 객체
        """
        self.llm_selector = llm_selector
        # 요청 캐싱을 위한 메모리 (간단한 구현)
        self.intent_cache = {}
        self.logger = logger

    def _get_analysis_llm(self):
        """의도 분석용 LLM을 선택합니다."""
        # 가능하면 작고 빠른 모델 선택
        llm = self.llm_selector.models.get('Claude')
        if not llm:
            # 없으면 기본 LLM 사용
            llm = self.llm_selector.default_model
        return llm

    def analyze_intent(self, question: str) -> dict:
        """
        사용자 질문의 의도를 종합적으로 분석합니다.

        Args:
            question (str): 사용자 질문

        Returns:
            dict: 분석 결과(의도 유형, 신뢰도 등)
        """
        # 캐시 확인
        normalized_question = question.strip().lower()
        if normalized_question in self.intent_cache:
            return self.intent_cache[normalized_question]

        # 빠른 검사 - 명확한 질문 패턴이 있는 경우 LLM 호출 없이 처리
        file_keywords = ["파일", "문서", "데이터", "자료"]
        if not any(keyword in normalized_question for keyword in file_keywords):
            result = {"intent": "other", "confidence": 0.9}
            self.intent_cache[normalized_question] = result
            return result

        # LLM 분석 시도
        try:
            # 경량 LLM 선택
            llm = self._get_analysis_llm()

            # 분석 프롬프트
            prompt = """
[지시사항]
다음 사용자 질문의 의도를 분석하여 아래 카테고리 중 하나로 분류해주세요.

<카테고리>
1. file_list: 시스템에 저장된 파일 목록을 요청하는 질문 
   - 예: "어떤 파일들이 있나요?", "저장된 문서 목록", "업로드된 데이터 확인"

2. file_specific: 특정 파일에 대한 정보나 내용을 요청하는 질문
   - 예: "report.pdf 파일에 대해 알려줘", "계획서 내용을 요약해줘"

3. file_status: 파일 처리 상태나 진행 상황을 묻는 질문
   - 예: "파일 처리 상태는 어떻게 되나요?", "문서 분석이 얼마나 진행됐나요?"

4. other: 파일과 관련 없는 일반적인 질문
   - 예: "오늘 날씨 어때?", "프로젝트 일정을 알려줘"

[사용자 질문]
{question}

[응답 형식]
다음 JSON 형식으로만 답변하세요:
{{
  "intent": "file_list/file_specific/file_status/other 중 하나",
  "confidence": 0.0~1.0 사이의 값(분류 확신도),
  "reasoning": "분류 이유에 대한 짧은 설명"
}}
"""
            # LLM 호출
            try:
                prompt_str = prompt.format(question=question)
                self.logger.info(f"Claude API 호출 시작")
                
                # Claude API 호출 - 메시지 형식
                messages = [HumanMessage(content=prompt_str)]
                response_obj = llm.invoke(messages)
                
                self.logger.info(f"Claude API 응답 수신: {type(response_obj)}")
                
            except Exception as invoke_error:
                self.logger.error(f"Claude API 호출 오류: {str(invoke_error)}")
                
            # 다양한 LLM 응답 형식 처리
            if hasattr(response_obj, 'content'):  # ChatAnthropic(Claude) 등의 경우
                response = response_obj.content
            elif isinstance(response_obj, str):  # 일부 모델은 직접 문자열 반환
                response = response_obj
            else:  # 그 외 다른 형태의 응답
                response = str(response_obj)

            json_pattern = r'\{.*\}'
            json_match = re.search(json_pattern, response, re.DOTALL)

            if json_match:
                try:
                    result = json.loads(json_match.group(0))
                    # 필수 필드 확인
                    if "intent" not in result:
                        result["intent"] = "other"
                    if "confidence" not in result:
                        result["confidence"] = 0.5

                    # 캐싱
                    result["method"] = "llm"
                    self.intent_cache[normalized_question] = result
                    return result
                except json.JSONDecodeError:
                    self.logger.warning("LLM 응답에서 JSON 파싱 실패")

            # JSON 파싱 실패 시 텍스트 기반 분석
            response_lower = response.lower()
            if "file_list" in response_lower:
                result = {"intent": "file_list", "confidence": 0.7, "method": "text_extraction"}
            elif "file_specific" in response_lower:
                result = {"intent": "file_specific", "confidence": 0.7, "method": "text_extraction"}
            elif "file_status" in response_lower:
                result = {"intent": "file_status", "confidence": 0.7, "method": "text_extraction"}
            else:
                result = {"intent": "other", "confidence": 0.7, "method": "text_extraction"}

            self.intent_cache[normalized_question] = result
            return result

        except Exception as e:
            self.logger.error(f"의도 분석 중 오류 발생: {str(e)}")
            # 오류 발생 시 백업으로 기본 키워드 검사
            if any(keyword in normalized_question for keyword in ["파일 목록", "어떤 파일", "파일이 있"]):
                return {"intent": "file_list", "confidence": 0.6, "method": "fallback"}
            else:
                return {"intent": "other", "confidence": 0.6, "method": "fallback"}

    def is_technical_content_llm(self, text: str) -> bool:
        """
        언어 모델을 사용하여 텍스트가 기술적 내용(코드, SQL, Docker 등)인지 판단합니다.

        Args:
            text (str): 분석할 텍스트

        Returns:
            bool: 기술적 내용이면 True, 아니면 False
        """
        # 캐시 확인
        import hashlib
        cache_key = hashlib.md5(text.encode()).hexdigest()
        if cache_key in self.intent_cache:
            cached_result = self.intent_cache[cache_key]
            if "is_technical" in cached_result:
                return cached_result["is_technical"]

        try:
            # 가벼운 모델 선택 (빠른 분류를 위해)
            classifier_llm = self._get_analysis_llm()

            # 분류 프롬프트
            prompt = """
    [지시사항]
    다음 텍스트가 프로그래밍 코드, SQL 쿼리, Docker 설정, 기술 문서, 기술적 지식 등의 
    기술적 내용을 포함하고 있는지 판단해주세요.

    [텍스트]
    {text}

    [응답 형식]
    다음 JSON 형식으로만 답변하세요:
    {{
      "is_technical": true/false,
      "confidence": 0.0~1.0 사이의 값,
      "category": "프로그래밍 코드, SQL, Docker, 기술 문서, 일반 내용 등",
      "reasoning": "판단 이유를 짧게 설명"
    }}
    """

            # LLM 호출
            try:
                # 안전한 import 시도
                try:
                    from langchain_core.messages import HumanMessage
                except ImportError:
                    try:
                        from langchain.schema import HumanMessage
                    except ImportError:
                        from langchain.schema.messages import HumanMessage
                
                prompt_str = prompt.format(text=text)
                self.logger.info(f"Claude API 호출 시작")
                
                # Claude API 호출 - 메시지 형식
                messages = [HumanMessage(content=prompt_str)]
                response_obj = classifier_llm.invoke(messages)
                
                self.logger.info(f"Claude API 응답 수신: {type(response_obj)}")
                
            except Exception as invoke_error:
                self.logger.error(f"Claude API 호출 오류: {str(invoke_error)}")
                # 더 자세한 오류 정보
                import traceback
                self.logger.error(f"상세 오류: {traceback.format_exc()}")
                
                # fallback으로 키워드 기반 분석 시도
                self.logger.info("키워드 기반 분석으로 fallback")
                return {"is_technical": False, "confidence": 0.5, "method": "error_fallback"}

            # 응답 처리
            if hasattr(response_obj, 'content'):
                response = response_obj.content
            elif isinstance(response_obj, str):
                response = response_obj
            else:
                response = str(response_obj)

            # JSON 추출
            import re
            import json

            json_pattern = r'\{.*\}'
            json_match = re.search(json_pattern, response, re.DOTALL)

            if json_match:
                try:
                    result = json.loads(json_match.group(0))
                    if "is_technical" in result:
                        # 캐싱
                        self.intent_cache[cache_key] = result
                        # 충분한 신뢰도를 가진 경우만 반환
                        if result.get("confidence", 0) > 0.6:
                            return result["is_technical"]
                except json.JSONDecodeError:
                    self.logger.warning("JSON 파싱 실패: LLM 기술 내용 감지")

            # 응답에서 true/false 직접 추출 시도
            if "true" in response.lower() and "technical" in response.lower():
                result = {"is_technical": True, "confidence": 0.7, "method": "text_extraction"}
                self.intent_cache[cache_key] = result
                return True

            # 결과가 불명확한 경우 기본 키워드 기반 탐지 사용
            is_technical = self._is_technical_content_keywords(text)
            result = {"is_technical": is_technical, "confidence": 0.6, "method": "fallback"}
            self.intent_cache[cache_key] = result
            return is_technical

        except Exception as e:
            self.logger.error(f"LLM 기술 내용 감지 오류: {str(e)}")
            # 오류 발생 시 기본 키워드 기반 탐지 사용
            is_technical = self._is_technical_content_keywords(text)
            result = {"is_technical": is_technical, "confidence": 0.5, "method": "error_fallback"}
            self.intent_cache[cache_key] = result
            return is_technical

    def _is_technical_content_keywords(self, text: str) -> bool:
        """키워드 기반으로 기술적 내용 탐지 (백업 방식)"""
        import re
        tech_keywords = ["코드", "프로그래밍", "sql", "쿼리", "docker", "컨테이너",
                         "함수", "메서드", "클래스", "알고리즘", "api", "데이터베이스",
                         "스크립트", "python", "javascript", "java", "c++", "html", "css"]

        code_patterns = [
            re.compile(r'def\s+\w+\s*\('),  # Python 함수 정의
            re.compile(r'SELECT\s+.+\s+FROM', re.IGNORECASE),  # SQL 쿼리
            re.compile(r'CREATE\s+TABLE', re.IGNORECASE),  # SQL 테이블 생성
            re.compile(r'FROM\s+\w+\s+WHERE', re.IGNORECASE),  # SQL 조건절
            re.compile(r'docker\s+run', re.IGNORECASE),  # Docker 실행 명령
            re.compile(r'class\s+\w+\s*[({:]'),  # 클래스 정의
            re.compile(r'function\s+\w+\s*\(')  # JavaScript 함수
        ]

        is_technical = any(keyword in text.lower() for keyword in tech_keywords)
        has_code_pattern = any(pattern.search(text) for pattern in code_patterns)

        return is_technical or has_code_pattern

    def is_file_list_request(self, question: str) -> bool:
        """
        사용자 질문이 파일 목록 요청인지 분석합니다.

        Args:
            question (str): 사용자 질문

        Returns:
            bool: 파일 목록 요청으로 판단되면 True
        """
        result = self.analyze_intent(question)

        # 높은 확신도로 file_list로 분류된 경우
        if result["intent"] == "file_list" and result["confidence"] >= 0.6:
            return True

        # 중간 확신도면 추가 키워드 검사
        elif result["intent"] == "file_list" and result["confidence"] >= 0.4:
            # 추가 검증을 위한 키워드 목록
            confirmation_keywords = [
                "파일", "문서", "데이터", "리스트", "목록", "보여", "있", "어떤"
            ]
            keyword_count = sum(1 for keyword in confirmation_keywords if keyword in question)
            return keyword_count >= 2

        return False

    def get_specific_file_info(self, question: str, file_list: list) -> dict:
        """
        특정 파일에 대한 요청 정보를 추출합니다.

        Args:
            question (str): 사용자 질문
            file_list (list): 사용자의 파일 목록

        Returns:
            dict: 파일명과 요청 유형
        """
        if not file_list:
            return {"is_specific_file": False}

        # 먼저 질문에 파일명이 직접 포함되는지 확인
        file_names = [file["filename"] for file in file_list]
        mentioned_files = [f for f in file_names if f in question]

        if mentioned_files:
            # 가장 긴 파일명을 선택 (더 구체적인 매칭)
            file_name = max(mentioned_files, key=len)

            # 요청 유형 판단 (간단한 키워드 기반)
            if any(kw in question for kw in ["요약", "설명", "개요"]):
                request_type = "요약"
            elif any(kw in question for kw in ["내용", "텍스트", "데이터"]):
                request_type = "내용"
            elif any(kw in question for kw in ["상태", "진행", "처리"]):
                request_type = "상태"
            else:
                request_type = "정보"

            return {
                "is_specific_file": True,
                "file_name": file_name,
                "request_type": request_type,
                "method": "direct_match"
            }

        # 직접 매칭 실패 시 LLM 분석 시도
        try:
            # LLM 선택
            intent_analysis_by_claude_llm = self._get_analysis_llm()

            # 파일명 목록
            file_names_str = ", ".join(file_names)

            # 분석 프롬프트
            prompt = """
    [지시사항]
    다음 사용자 질문이 특정 파일에 관한 것인지 분석해주세요.

    [사용자의 파일 목록]
    {file_list}

    [사용자 질문]
    {question}

    [응답 형식]
    다음 JSON 형식으로만 답변하세요:
    {{
      "is_specific_file": true/false,
      "file_name": "언급된 파일명 또는 빈 문자열",
      "request_type": "요약/내용/상태/정보 중 하나",
      "reasoning": "판단 이유를 짧게 설명"
    }}
    """
            # LLM 호출
            try:
                # 안전한 import 시도
                from langchain_core.messages import HumanMessage
                
                prompt_str = prompt.format(question=question, file_list=file_names_str)
                self.logger.info(f"Claude API 호출 시작")
                
                # Claude API 호출 - 메시지 형식
                messages = [HumanMessage(content=prompt_str)]
                response_obj = intent_analysis_by_claude_llm.invoke(messages)
                
                self.logger.info(f"Claude API 응답 수신: {type(response_obj)}")
                
            except Exception as invoke_error:
                self.logger.error(f"Claude API 호출 오류: {str(invoke_error)}")
                # 더 자세한 오류 정보
                import traceback
                self.logger.error(f"상세 오류: {traceback.format_exc()}")
                
                # fallback으로 키워드 기반 분석 시도
                self.logger.info("키워드 기반 분석으로 fallback")
                return {"is_specific_file": False}

            # 다양한 LLM 응답 형식 처리
            if hasattr(response_obj, 'content'):  # ChatAnthropic(Claude) 등의 경우
                response = response_obj.content
            elif isinstance(response_obj, str):  # 일부 모델은 직접 문자열 반환
                response = response_obj
            else:  # 그 외 다른 형태의 응답
                response = str(response_obj)

            # JSON 추출
            import re
            import json

            json_pattern = r'\{.*\}'
            json_match = re.search(json_pattern, response, re.DOTALL)

            if json_match:
                try:
                    result = json.loads(json_match.group(0))

                    # 'is_specific_file' 필드가 있는지 확인
                    if "is_specific_file" in result:
                        # LLM의 결정에 method 정보 추가
                        result["method"] = "llm"

                        # 파일 관련 질문이라면 파일명 유효성 검사 추가
                        if result.get("is_specific_file") and result.get("file_name"):
                            # 파일명이 실제로 존재하는지 확인
                            if result["file_name"] in file_names:
                                return result
                            else:
                                # 파일명이 존재하지 않으면 is_specific_file을 False로 설정
                                result["is_specific_file"] = False
                                result["reasoning"] = "파일명이 사용자 파일 목록에 존재하지 않습니다."
                                return result
                        else:
                            # 파일 관련 질문이 아니면 그대로 반환
                            return result
                except json.JSONDecodeError:
                    self.logger.warning("LLM 응답에서 JSON 파싱 실패")

        except Exception as e:
            self.logger.error(f"특정 파일 분석 중 오류 발생: {str(e)}")

        # 모든 분석이 실패한 경우
        return {"is_specific_file": False}