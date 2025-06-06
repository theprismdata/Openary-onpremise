import json
import sys
from enum import Enum
import requests
from langchain_community.llms.ollama import Ollama
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from typing import Optional
from langchain.llms.base import LLM
from huggingface_hub import InferenceClient
from pydantic import BaseModel, Field
from typing import Dict
from typing import List
from typing import Any

from LLMIntentAnalyzer import LLMIntentAnalyzer


class QuestionIntent(Enum):
    ANALYTICAL = "analytical"    # 데이터 분석, 비즈니스 분석
    CREATIVE = "creative"        # 창의적 글쓰기, 아이디어 제안
    TECHNICAL = "technical"      # 기술 문서, 코드 관련
    REASONING = "reasoning"      # 복잡한 추론, 의사결정
    GENERAL = "general"         # 일반적인 대화


class HuggingFaceInference(LLM):
    client: Optional[InferenceClient] = None
    model: str = Field(..., description="The model to use for inference")
    api_key: str = Field(..., description="HuggingFace API key")
    temperature: float = Field(default=0.7, description="Sampling temperature")
    max_tokens: int = Field(default=500, description="Maximum number of tokens to generate")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client = InferenceClient(provider="hf-inference", model=self.model, token=self.api_key)

    def _call(self, prompt: str, stop: Optional[List[str]] = None) -> str:
        response = self.client.text_generation(
            prompt,
            temperature=self.temperature,
            max_new_tokens=self.max_tokens,
            repetition_penalty=1.03,
        )
        return response

    @property
    def _llm_type(self) -> str:
        return "huggingface_inference"

    @property
    def _identifying_params(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

class LLMSelector:
    def __init__(self, Ollama_model, Ollama_address, logger, config: dict):
        self.config = config
        self.models = {}
        self.RUN_MODE = 'API'
        self.default_model = None
        self.logger = logger
        self.Ollama_model = Ollama_model
        self.Ollama_address = Ollama_address
        self._initialize_llms()
        self._set_default_model()

    def download_ollama(self):
        try:
            self.logger.info("Ollama model check")
            method = "api/tags"
            url = f"{self.Ollama_address}/{method}"
            headers = {'Content-Type': 'application/json', 'charset': 'UTF-8', 'Accept': '*/*'}

            response = requests.get(url, headers=headers)
            model_list = []
            if response.status_code == 200:
                rtn_json = response.json()
                models = rtn_json['models']
                if len(models) > 0:
                    for model_meta in models:
                        model_list.append(model_meta['model'])

            if self.Ollama_model not in model_list:
                self.logger.info(f"Ollama {self.Ollama_model} pull")
                method = "api/pull"
                url = f"{self.Ollama_address}/{method}"
                headers = {'Content-Type': 'application/json', 'charset': 'UTF-8', 'Accept': '*/*'}
                body = {"model": self.Ollama_model}
                response = requests.post(url, headers=headers,
                                         data=json.dumps(body, ensure_ascii=False, indent="\t"))
                if response.status_code == 200:
                    rtn_text = response.text
                    print(rtn_text)
            else:
                self.logger.info(f"Ollama {self.Ollama_model} found")
        except Exception as e:
            print(f"Error connecting to Ollama server: {e}")
            print("Please make sure the Ollama server is running (Ollama serve)")
            sys.exit(1)

    def _initialize_llms(self):
        """LLM 초기화"""
        try:
            self.RUN_MODE = self.config['langmodel']['RUN_MODE']
            if self.RUN_MODE == 'LOCAL':
                # Ollama 초기화
                if 'Ollama' in self.config['langmodel']['LOCAL']:
                    self.models['Ollama'] = Ollama(
                        model=self.config['langmodel']['LOCAL']['Ollama']['chat_model'],
                        base_url=self.config['langmodel']['LOCAL']['Ollama']['address']
                    )
                    # load model
                    self.download_ollama()
            elif self.RUN_MODE == 'API':
                # Claude 초기화
                if 'Claude' in self.config['langmodel']['API']:
                    self.models['Claude'] = ChatAnthropic(
                        model=self.config['langmodel']['API']['Claude']['chat_model'],
                        anthropic_api_key=self.config['langmodel']['API']['Claude']['apikey'],
                        temperature=0.7,
                        streaming=True  # 스트리밍 활성화
                    )

                # Gemma 초기화 (주석 처리)
                """
                if 'huggingface' in self.config['langmodel']['API']:
                    self.models['Gemma'] = HuggingFaceInference(
                        model=self.config['langmodel']['API']['huggingface']['model'],
                        api_key=self.config['langmodel']['API']['huggingface']['api_key'],
                        temperature=self.config['langmodel']['API']['huggingface']['temperature'],
                        max_tokens=self.config['langmodel']['API']['huggingface']['max_token'],
                    )
                """

                # OpenAI 초기화
                if 'OpenAI' in self.config['langmodel']['API']:
                    self.models['OpenAI'] = ChatOpenAI(
                        model=self.config['langmodel']['API']['OpenAI']['chat_model'],
                        temperature=0,
                        max_tokens=1000,
                        openai_api_key=self.config['langmodel']['API']['OpenAI']['apikey'],
                        streaming=True  # 스트리밍 활성화
                    )

                # Remote Ollama 초기화
                if 'Remote' in self.config['langmodel']['API'] and 'Ollama' in self.config['langmodel']['API'][
                    'Remote']:
                    self.models['RemoteOllama'] = Ollama(
                        model=self.config['langmodel']['API']['Remote']['Ollama']['chat_model'],
                        base_url=self.config['langmodel']['API']['Remote']['Ollama']['address']
                    )

        except Exception as e:
            self.logger.error(f"Error initializing LLMs: {str(e)}")
            raise

    def _set_default_model(self):
        """기본 모델 설정"""
        # Remote의 Ollama를 기본 모델로 설정
        if self.RUN_MODE == 'API':
            self.default_model = self.models.get('RemoteOllama')

            if self.default_model is None:
                # Huggingface는 주석 처리했으므로 OpenAI와 Claude만 남음
                self.default_model = self.models.get('OpenAI', self.models.get('Claude'))

        elif self.RUN_MODE == 'LOCAL':
            self.default_model = self.models.get('Ollama')

        if self.default_model is None:
            raise ValueError("No LLM models available")

    def _classify_intent(self, question: str) -> QuestionIntent:
        """LLM을 사용하여 질문의 의도를 분류하는 함수"""
        if self.RUN_MODE == 'LOCAL':
            return QuestionIntent.GENERAL
        else:
            if question == "default":
                return QuestionIntent.GENERAL
            classification_prompt = """아래 질문의 의도를 분석하여 가장 적절한 카테고리를 선택해주세요.
        질문: {question}
        카테고리는 다음과 같습니다:
        1. ANALYTICAL (데이터 분석, 비즈니스 분석)
           - 데이터 기반 분석이 필요한 질문
           - 비즈니스 성과, 시장 분석 관련 질문
           - 통계적 분석이나 트렌드 파악이 필요한 질문

        2. TECHNICAL (기술적 문제)
           - 개발, 프로그래밍 관련 질문
           - 시스템 설계, 아키텍처 관련 질문
           - 기술적 문제 해결이나 구현 관련 질문

        3. REASONING (추론, 의사결정)
           - 복잡한 문제 해결이 필요한 질문
           - 전략적 의사결정이 필요한 질문
           - 인과관계 분석이나 영향 평가가 필요한 질문

        4. CREATIVE (창의적 작업)
           - 새로운 아이디어나 혁신이 필요한 질문
           - 기획, 디자인 관련 질문
           - 창의적인 콘텐츠 제작 관련 질문

        5. GENERAL (일반적인 질문)
           - 위 카테고리에 명확하게 속하지 않는 일반적인 질문
        응답 형식: 카테고리 이름만 답변해주세요 (ANALYTICAL, TECHNICAL, REASONING, CREATIVE, GENERAL 중 하나)

        분류 결과:"""
            try:
                # Gemma 대신 RemoteOllama 또는 다른 가용 모델 선택
                # 첫 번째로 사용 가능한 모델을 사용
                classifier_llm = None
                if 'RemoteOllama' in self.models:
                    classifier_llm = self.models.get('RemoteOllama')
                elif 'OpenAI' in self.models:
                    classifier_llm = self.models.get('OpenAI')
                elif 'Claude' in self.models:
                    classifier_llm = self.models.get('Claude')
                else:
                    classifier_llm = self.default_model

                # LLM에 분류 요청
                response = classifier_llm(classification_prompt.format(question=question))

                # 응답에서 카테고리 추출
                response = response.strip().upper()

                # 유효한 카테고리인 경우 해당 카테고리 반환
                for intent in QuestionIntent:
                    if intent.value.upper() in response:
                        return intent

                return QuestionIntent.GENERAL

            except Exception as e:
                self.logger.error(f"Error in LLM intent classification: {str(e)}")
                return QuestionIntent.GENERAL

    def select_llm(self, question: str) -> Optional[LLM]:
        """질문 의도에 따라 최적의 LLM 선택"""
        # default 문자열이 입력된 경우 기본 모델 반환
        if self.RUN_MODE == 'API':
            if question == "default":
                return self.default_model

            # 기술적 내용 감지
            is_technical = False
            try:
                intent_analyzer = LLMIntentAnalyzer(self.logger, self)
                is_technical = intent_analyzer.is_technical_content_llm(question)

                # 기술적 내용이면 Claude 선택
                if is_technical:
                    claude = self.models.get('Claude')
                    if claude:
                        self.logger.info("기술적 내용 감지: Claude 모델 선택")
                        return claude
            except Exception as e:
                self.logger.error(f"기술 내용 감지 오류: {str(e)}")

            # 기존 로직 계속 진행
            try:
                intent = self._classify_intent(question)
                if intent == QuestionIntent.ANALYTICAL:
                    return self.models.get('OpenAI')

                elif intent == QuestionIntent.TECHNICAL:
                    # TECHNICAL 의도는 항상 Claude 사용 (코드/기술 문서 관련)
                    claude = self.models.get('Claude')
                    return claude if claude else self.default_model

                elif intent == QuestionIntent.REASONING:
                    return self.models.get('Claude')

                elif intent == QuestionIntent.CREATIVE:
                    return self.models.get('OpenAI')

                else:  # GENERAL
                    return self.default_model
            except Exception as e:
                self.logger.error(f"Error selecting LLM: {str(e)}")
                return self.default_model
        else:
            return self.models.get('Ollama')

    def get_llm_info(self, llm: LLM) -> str:
        """선택된 LLM 정보 반환"""
        if isinstance(llm, ChatAnthropic):
            return "Claude"
        elif isinstance(llm, HuggingFaceInference):
            return "Gemma"
        elif isinstance(llm, ChatOpenAI):
            return "OpenAI"
        elif isinstance(llm, Ollama):
            return "Ollama"
        return "Unknown LLM"