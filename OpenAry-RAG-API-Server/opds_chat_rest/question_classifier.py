class QuestionClassifier:
    """
    질문 유형을 분류하여 내부 DB를 사용해야 하는지(RAG) 또는
    외부 검색을 해야 하는지(AGENT) 판단하는 클래스
    """

    def __init__(self, llm_selector, logger):
        """
        Args:
            llm_selector (LLMSelector): LLM 선택기 객체
            logger: 로깅 객체
        """
        self.llm_selector = llm_selector
        self.logger = logger
        self.classification_cache = {}  # 분류 결과 캐싱

        # 내부 문서 관련 키워드
        self.INTERNAL_KEYWORDS = [
            "문서", "파일", "업로드", "데이터", "내부", "시스템", "보고서",
            "자료", "내용", "저장", "기록", "정보", "첨부", "csv", "엑셀", "pdf",
            "우리", "회사", "조직", "팀", "부서", "프로젝트"
        ]

        # 외부 검색 관련 키워드
        self.EXTERNAL_KEYWORDS = [
            "검색", "최신", "뉴스", "기사", "외부", "인터넷", "웹", "사이트",
            "날씨", "주가", "이슈", "트렌드", "시장", "업데이트", "최근", "현재"
        ]

        # 시간 관련 키워드 (최신 정보 필요성 암시)
        self.TEMPORAL_KEYWORDS = [
            "오늘", "어제", "최근", "이번 주", "이번 달", "올해", "작년",
            "2023년", "2024년", "2025년", "현재", "지금"
        ]

    def _quick_check(self, question):
        """
        키워드 기반 빠른 검사로 명확한 경우 즉시 결정

        Args:
            question (str): 사용자 질문

        Returns:
            str or None: 'rag', 'agent', 또는 명확하지 않은 경우 None
        """
        normalized_question = question.lower()

        # 내부 키워드 점수 계산
        internal_score = sum(1 for keyword in self.INTERNAL_KEYWORDS
                             if keyword in normalized_question)

        # 외부 키워드 점수 계산
        external_score = sum(1 for keyword in self.EXTERNAL_KEYWORDS
                             if keyword in normalized_question)

        # 시간 관련 키워드는 외부 검색 가능성을 높임
        temporal_score = sum(1 for keyword in self.TEMPORAL_KEYWORDS
                             if keyword in normalized_question)

        external_score += temporal_score * 0.5

        # 점수 차이가 크면 빠르게 결정
        if internal_score > external_score + 2:
            return "rag"
        elif external_score > internal_score + 2:
            return "agent"

        # 명확한 파일명 언급 확인 (확장자 포함)
        file_extensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt"]
        if any(ext in normalized_question for ext in file_extensions):
            return "rag"

        return None  # 확실하지 않은 경우

    def _llm_classify(self, question):
        """
        LLM을 사용한 분류가 필요한 경우

        Args:
            question (str): 사용자 질문

        Returns:
            dict: 분류 결과와 신뢰도
        """
        try:
            # 분류용 LLM 선택 (가능하면 경량 모델)
            llm = self.llm_selector.models.get('Gemma', self.llm_selector.default_model)

            # 분류 프롬프트
            prompt = """
[지시사항]
다음 사용자 질문을 분석하여, 질문에 답변하기 위해 내부 문서 검색(RAG)을 사용해야 하는지, 
아니면 외부 인터넷 검색(Agent)을 사용해야 하는지 분류해주세요.

[분류 기준]
1. 내부 문서 검색(RAG)이 적합한 경우:
   - 사용자가 업로드한 파일이나 내부 문서에 대한 질문
   - 시스템에 저장된 데이터나 정보에 대한 질문
   - 특정 파일이나 문서의 내용에 대한 질문
   - 과거에 기록된 정보에 대한 질문

2. 외부 인터넷 검색(Agent)이 적합한 경우:
   - 최신 뉴스, 시장 동향, 실시간 정보가 필요한 질문
   - 내부 문서에 없을 가능성이 높은 일반 지식 질문
   - 시간에 민감한 정보(날씨, 주가, 최신 이벤트 등)에 대한 질문
   - 광범위한 검색이 필요한 주제에 대한 질문

[사용자 질문]
{question}

[응답 형식]
다음 JSON 형식으로만 답변하세요:
{{
  "classification": "rag" 또는 "agent",
  "confidence": 0.0~1.0 사이의 값,
  "reasoning": "분류 이유에 대한 짧은 설명"
}}
"""

            # LLM 호출
            response_obj = llm(prompt.format(question=question))

            # LLM 응답 형식에 따른 처리
            if hasattr(response_obj, 'content'):
                response = response_obj.content
            else:
                response = str(response_obj)

            # JSON 파싱
            import re
            import json

            json_pattern = r'\{.*\}'
            json_match = re.search(json_pattern, response, re.DOTALL)

            if json_match:
                try:
                    result = json.loads(json_match.group(0))
                    if "classification" in result:
                        return result
                except json.JSONDecodeError:
                    self.logger.warning("LLM 응답에서 JSON 파싱 실패")

            # 파싱 실패 시 텍스트 기반 분석
            if "rag" in response.lower():
                return {"classification": "rag", "confidence": 0.6, "reasoning": "텍스트 분석 기반 추정"}
            elif "agent" in response.lower() or "external" in response.lower():
                return {"classification": "agent", "confidence": 0.6, "reasoning": "텍스트 분석 기반 추정"}

            # 기본값
            return {"classification": "rag", "confidence": 0.5, "reasoning": "기본값 반환"}

        except Exception as e:
            self.logger.error(f"LLM 분류 중 오류: {str(e)}")
            return {"classification": "rag", "confidence": 0.5, "reasoning": "오류 발생으로 기본값 반환"}

    def _check_for_file_presence(self, question, user_files):
        """
        질문에 언급된 파일이 실제로 존재하는지 확인

        Args:
            question (str): 사용자 질문
            user_files (list): 사용자 파일 목록

        Returns:
            bool: 파일 존재 여부
        """
        if not user_files:
            return False

        # 파일 이름 추출
        file_names = [file['filename'] for file in user_files]

        # 질문에 파일 이름이 포함되어 있는지 확인
        for file_name in file_names:
            if file_name in question:
                return True

        return False

    def _analyze_question_complexity(self, question):
        """
        질문의 복잡성 분석

        Args:
            question (str): 사용자 질문

        Returns:
            float: 복잡성 점수 (0.0~1.0)
        """
        # 단어 수로 기본 복잡성 측정
        words = question.split()
        word_count = len(words)

        # 복잡한 구조를 나타내는 키워드
        complex_indicators = [
            "비교", "분석", "관계", "추세", "경향", "예측", "추론", "패턴",
            "원인", "결과", "영향", "상관관계", "차이", "유사점", "분류"
        ]

        # 복잡성 점수 계산
        complexity_indicators_count = sum(1 for indicator in complex_indicators
                                          if indicator in question)

        # 기본 복잡성 (단어 수 기반)
        base_complexity = min(1.0, word_count / 30.0)

        # 지표 기반 가중치 추가
        indicator_weight = min(0.5, complexity_indicators_count * 0.1)

        return base_complexity + indicator_weight

    def classify(self, question, user_files=None):
        """
        질문을 분석하여 RAG 또는 Agent 방식으로 처리해야 하는지 결정

        Args:
            question (str): 사용자 질문
            user_files (list, optional): 사용자의 파일 목록

        Returns:
            dict: 분류 결과
                {
                    "method": "rag" 또는 "agent",
                    "confidence": 0.0~1.0,
                    "reasoning": "분류 이유"
                }
        """
        # 캐시 확인
        if question in self.classification_cache:
            return self.classification_cache[question]

        # 1단계: 빠른 키워드 검사
        quick_result = self._quick_check(question)
        if quick_result:
            result = {
                "method": quick_result,
                "confidence": 0.85,
                "reasoning": "키워드 기반 빠른 분류"
            }
            self.classification_cache[question] = result
            return result

        # 2단계: 파일 존재 여부 확인
        if user_files and self._check_for_file_presence(question, user_files):
            result = {
                "method": "rag",
                "confidence": 0.9,
                "reasoning": "질문에 언급된 파일이 존재함"
            }
            self.classification_cache[question] = result
            return result

        # 3단계: 질문 복잡성 분석
        complexity = self._analyze_question_complexity(question)

        # 복잡한 질문은 RAG 우선(내부 데이터 기반 분석이 필요할 가능성)
        if complexity > 0.7:
            result = {
                "method": "rag",
                "confidence": 0.75,
                "reasoning": "복잡한 질문 구조로 내부 데이터 분석 필요"
            }
            self.classification_cache[question] = result
            return result

        # 4단계: LLM 기반 분류
        llm_result = self._llm_classify(question)

        result = {
            "method": llm_result["classification"],
            "confidence": llm_result["confidence"],
            "reasoning": llm_result["reasoning"]
        }

        # 캐싱
        self.classification_cache[question] = result
        return result

    def should_use_rag(self, question, user_files=None, threshold=0.6):
        """
        RAG를 사용해야 하는지 여부를 판단 (간편 인터페이스)

        Args:
            question (str): 사용자 질문
            user_files (list, optional): 사용자 파일 목록
            threshold (float): 판단 임계값

        Returns:
            bool: RAG를 사용해야 하면 True, Agent를 사용해야 하면 False
        """
        result = self.classify(question, user_files)

        if result["method"] == "rag" and result["confidence"] >= threshold:
            return True
        elif result["method"] == "agent" and result["confidence"] >= threshold:
            return False

        # 불확실한 경우 기본값으로 RAG 선택
        return True