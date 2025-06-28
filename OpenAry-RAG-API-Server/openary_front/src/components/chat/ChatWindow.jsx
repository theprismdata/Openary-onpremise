import { useState, useEffect, useCallback } from "react";
import { useSelector } from "react-redux";
import { sendMessage, getSessionList } from "../../services/chatService";
import ChatHistory from "./ChatHistory";
import ChatMessage from "./ChatMessage";
import MessageInput from "./MessageInput";
import LoadingMessage from "./LoadingMessage";
import FileDashboard from "../../components/dashboard/FileDashboard";
import axios from "../../utils/axios_chatapi";
import { Mic, MicOff, Volume2, VolumeX } from "lucide-react";

export default function ChatWindow() {
  const [messages, setMessages] = useState([]);
  const [sessionId, setSessionId] = useState(0);
  const [sessions, setSessions] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showDashboard, setShowDashboard] = useState(() => {
    const saved = sessionStorage.getItem("dashboardView");
    return saved ? JSON.parse(saved) : false;
  });
  const [isListening, setIsListening] = useState(false);
  const [transcript, setTranscript] = useState("");
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [voices, setVoices] = useState([]);
  const [selectedVoice, setSelectedVoice] = useState(null);
  // 스트리밍 항상 사용으로 설정 (useStreaming 상태 제거)
  const { user, token } = useSelector((state) => state.auth);

  // 스트리밍 메시지 전송 함수 (컴포넌트 내부로 이동)
  const sendStreamingMessage = async (messageData) => {
    // axios_chatapi에서 baseURL 가져오기
    const baseURL = axios.defaults.baseURL;
    const response = await fetch(`${baseURL}/rqa_stream`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(messageData),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.body;
  };

  // 마크다운 제거 함수
  const removeMarkdown = useCallback((text) => {
    return text
      .replace(/`{3}[\s\S]*?`{3}/g, "") // 코드 블록 제거
      .replace(/`(.+?)`/g, "$1") // 인라인 코드 제거
      .replace(/\*\*(.+?)\*\*/g, "$1") // 볼드 제거
      .replace(/\*(.+?)\*/g, "$1") // 이탤릭 제거
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1") // 링크 제거
      .replace(/#{1,6}\s+/g, "") // 헤더 제거
      .replace(/(\*|-|\+)\s/g, "") // 불렛 포인트 제거
      .replace(/\n\d+\.\s/g, "\n") // 숫자 리스트 제거
      .replace(/\n{2,}/g, "\n") // 여러 줄 바꿈을 하나로
      .trim();
  }, []);

  // 음성 목록 초기화
  useEffect(() => {
    const loadVoices = () => {
      const synthesis = window.speechSynthesis;
      const availableVoices = synthesis.getVoices();
      const googleKoreanVoice = availableVoices.find(
        (voice) => voice.name.includes("Google") && voice.lang === "ko-KR"
      );

      if (googleKoreanVoice) {
        setSelectedVoice(googleKoreanVoice);
      } else {
        console.warn("Google Korean voice not found");
      }
    };

    if ("speechSynthesis" in window) {
      window.speechSynthesis.onvoiceschanged = loadVoices;
      loadVoices();
    }

    return () => {
      if ("speechSynthesis" in window) {
        window.speechSynthesis.onvoiceschanged = null;
      }
    };
  }, []);

  // 스트리밍 메시지 전송 처리
  const handleStreamingMessage = useCallback(
    async (question) => {
      setIsLoading(true);

      try {
        // 사용자 메시지만 먼저 추가
        setMessages((prev) => [
          ...prev,
          {
            id: `user-${prev.length}-${Date.now()}-${Math.random()
              .toString(36)
              .substr(2, 9)}`,
            type: "user",
            content: question,
          },
        ]);

        const streamResponse = await sendStreamingMessage({
          email: user.email,
          question,
          session_id: sessionId,
          isnewsession: sessionId === 0,
        });

        const reader = streamResponse.getReader();
        const decoder = new TextDecoder();
        let done = false;
        let responseText = "";
        let botMessageId = null;
        let sources = [];
        let searchResults = [];
        let firstChunkReceived = false;

        while (!done) {
          const { value, done: doneReading } = await reader.read();
          done = doneReading;

          if (done) break;

          const chunk = decoder.decode(value);
          const lines = chunk.split("\n").filter((line) => line.trim());

          for (const line of lines) {
            try {
              const data = JSON.parse(line);

              // 청크 타입에 따른 처리
              switch (data.type) {
                case "session":
                  if (sessionId === 0) {
                    const newSessionId = data.session_id;
                    setSessionId(newSessionId);
                    setSessions((prev) => [
                      {
                        [newSessionId]: question.substring(0, 30) + "...",
                      },
                      ...prev,
                    ]);
                  }
                  break;

                case "metadata":
                  sources = data.sources || [];
                  searchResults = data.search_results || [];
                  break;

                case "chunk":
                  // 첫 번째 청크를 받았을 때만 메시지 생성
                  if (!firstChunkReceived) {
                    firstChunkReceived = true;
                    botMessageId = `bot-${
                      messages.length
                    }-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

                    // 첫 청크를 받았을 때 봇 메시지 추가
                    setMessages((prev) => [
                      ...prev,
                      {
                        id: botMessageId,
                        type: "bot",
                        content: data.content,
                        sources,
                        searchResults,
                        isComplete: false, // 스트리밍 중이므로 미완료 상태
                      },
                    ]);
                    responseText = data.content;
                  } else {
                    responseText += data.content;

                    // 이후 청크는 기존 메시지 업데이트
                    setMessages((prev) =>
                      prev.map((msg) =>
                        msg.id === botMessageId
                          ? {
                              ...msg,
                              content: responseText,
                              sources,
                              searchResults,
                              isComplete: false, // 스트리밍 중이므로 미완료 상태
                            }
                          : msg
                      )
                    );
                  }
                  break;

                case "done":
                  // 스트리밍 완료
                  if (botMessageId) {
                    setMessages((prev) =>
                      prev.map((msg) =>
                        msg.id === botMessageId
                          ? {
                              ...msg,
                              content: responseText,
                              sources,
                              searchResults,
                              isComplete: true, // 완료 플래그 설정
                            }
                          : msg
                      )
                    );
                  }
                  break;

                case "error":
                  throw new Error(data.error);

                default:
                  console.warn("Unknown chunk type:", data);
              }
            } catch (e) {
              console.error("Failed to parse streaming chunk:", e, line);
            }
          }
        }

        // 만약 응답이 없었다면 오류 메시지 표시
        if (!firstChunkReceived) {
          setMessages((prev) => [
            ...prev,
            {
              id: `error-${prev.length}-${Date.now()}-${Math.random()
                .toString(36)
                .substr(2, 9)}`,
              type: "bot",
              content: "응답을 받지 못했습니다. 다시 시도해 주세요.",
            },
          ]);
        }
      } catch (error) {
        console.error("Failed to process streaming message:", error);

        // 오류 메시지 추가
        setMessages((prev) => [
          ...prev,
          {
            id: `error-${prev.length}-${Date.now()}-${Math.random()
              .toString(36)
              .substr(2, 9)}`,
            type: "bot",
            content:
              "죄송합니다. 메시지 처리 중 오류가 발생했습니다. 다시 시도해 주세요.",
            sources: [],
            searchResults: [],
          },
        ]);
      } finally {
        setIsLoading(false);
      }
    },
    [sessionId, user, token, messages.length, sendStreamingMessage]
  );

  // 비스트리밍 메시지 전송 처리 함수 - 하위 호환성을 위해 유지
  const handleSendMessage = useCallback(
    async (question) => {
      setIsLoading(true);
      try {
        setMessages((prev) => [
          ...prev,
          {
            id: `user-${prev.length}-${Date.now()}-${Math.random()
              .toString(36)
              .substr(2, 9)}`,
            type: "user",
            content: question,
          },
        ]);

        const response = await sendMessage(
          {
            email: user.email,
            question,
            session_id: sessionId,
            isnewsession: sessionId === 0,
          },
          token
        );

        setMessages((prev) => [
          ...prev,
          {
            id: `bot-${prev.length}-${Date.now()}-${Math.random()
              .toString(36)
              .substr(2, 9)}`,
            type: "bot",
            content: response.answer,
            sources: response.sourcelist,
            searchResults: response.searchlist,
          },
        ]);

        if (sessionId === 0) {
          setSessionId(response.chat_session);
          setSessions((prev) => [
            {
              [response.chat_session]: question.substring(0, 30) + "...",
            },
            ...prev,
          ]);
        }
      } catch (error) {
        console.error("Failed to send message:", error);
        setMessages((prev) => [
          ...prev,
          {
            id: `error-${prev.length}-${Date.now()}-${Math.random()
              .toString(36)
              .substr(2, 9)}`,
            type: "bot",
            content:
              "죄송합니다. 메시지 처리 중 오류가 발생했습니다. 다시 시도해 주세요.",
          },
        ]);
      } finally {
        setIsLoading(false);
      }
    },
    [sessionId, user, token]
  );

  // 사용자 메시지 처리 - 항상 스트리밍 메시지 사용
  const handleMessageSubmit = useCallback(
    (question) => {
      handleStreamingMessage(question);
    },
    [handleStreamingMessage]
  );

  // STT 초기화
  const recognition = useCallback(() => {
    if ("webkitSpeechRecognition" in window) {
      const recognition = new window.webkitSpeechRecognition();
      recognition.continuous = false;
      recognition.interimResults = true;
      recognition.lang = "ko-KR";
      return recognition;
    }
    return null;
  }, []);

  // STT 시작
  const startListening = useCallback(() => {
    if (!recognition) {
      alert("죄송합니다. 이 브라우저는 음성 인식을 지원하지 않습니다.");
      return;
    }

    const recognitionInstance = recognition();

    recognitionInstance.onstart = () => {
      setIsListening(true);
      setTranscript("");
    };

    recognitionInstance.onresult = (event) => {
      const current = event.resultIndex;
      const transcript = event.results[current][0].transcript;
      setTranscript(transcript);
    };

    recognitionInstance.onend = () => {
      setIsListening(false);
      if (transcript.trim()) {
        handleMessageSubmit(transcript.trim());
        setTranscript("");
      }
    };

    recognitionInstance.onerror = (event) => {
      console.error("Speech recognition error:", event.error);
      setIsListening(false);
    };

    recognitionInstance.start();
  }, [recognition, handleMessageSubmit, transcript]);

  // STT 중지
  const stopListening = useCallback(() => {
    if (recognition) {
      const recognitionInstance = recognition();
      recognitionInstance.stop();
      setIsListening(false);
    }
  }, [recognition]);

  // TTS 실행
  const speak = useCallback(
    (text) => {
      const synthesis = window.speechSynthesis;

      if (!synthesis || !selectedVoice) {
        alert("Google 한국어 음성을 찾을 수 없습니다.");
        return;
      }

      // 모든 음성 취소
      synthesis.cancel();

      // 재생 중이면 중지
      if (isSpeaking) {
        setIsSpeaking(false);
        return;
      }

      // 마크다운 제거
      const cleanText = removeMarkdown(text);

      const utterance = new SpeechSynthesisUtterance(cleanText);
      utterance.voice = selectedVoice;
      utterance.rate = 1.0;
      utterance.pitch = 1.0;

      // Chrome 버그 해결을 위한 주기적인 resume 호출
      const resumeInterval = setInterval(() => {
        if (synthesis.speaking) {
          synthesis.resume();
        } else {
          clearInterval(resumeInterval);
        }
      }, 5000);

      utterance.onstart = () => {
        setIsSpeaking(true);
      };

      utterance.onend = () => {
        setIsSpeaking(false);
        clearInterval(resumeInterval);
      };

      utterance.onerror = (event) => {
        if (event.error !== "interrupted") {
          console.error("TTS Error:", event);
        }
        setIsSpeaking(false);
        clearInterval(resumeInterval);
      };

      // 음성 재생 시작
      setTimeout(() => {
        synthesis.speak(utterance);
      }, 100);
    },
    [isSpeaking, removeMarkdown, selectedVoice]
  );

  // 세션 목록 가져오기
  const fetchSessionList = async () => {
    try {
      const response = await getSessionList(user.email, token);
      setSessions(response.session_list);
    } catch (error) {
      console.error("Failed to fetch sessions:", error);
    }
  };

  // 세션 히스토리 가져오기
  const fetchSessionHistory = async (selectedSessionId) => {
    setIsLoading(true);
    try {
      const response = await axios.post("/getasessionhistory", {
        email: user.email,
        session: selectedSessionId,
      });

      if (response.data) {
        const historyMessages = response.data.history.flatMap((item, index) => [
          {
            id: `user-${index}-${Date.now()}-${Math.random()
              .toString(36)
              .substr(2, 9)}`,
            type: "user",
            content: item.question,
          },
          {
            id: `bot-${index}-${Date.now()}-${Math.random()
              .toString(36)
              .substr(2, 9)}`,
            type: "bot",
            content: item.answer,
            sources: item.sourcelist,
            searchResults: item.searchlist,
          },
        ]);

        setMessages(historyMessages);
      }
    } catch (error) {
      console.error("Failed to fetch session history:", error);
    } finally {
      setIsLoading(false);
    }
  };

  // 세션 선택 처리
  const handleSessionSelect = useCallback((selectedSessionId) => {
    setSessionId(selectedSessionId);
    fetchSessionHistory(selectedSessionId);
  }, []);

  // 대시보드 토글 처리
  const handleToggleDashboard = useCallback((isDocs) => {
    sessionStorage.setItem("dashboardView", JSON.stringify(isDocs));
    setShowDashboard(isDocs);
  }, []);

  // 초기 세션 목록 로드
  useEffect(() => {
    const fetchSessions = async () => {
      try {
        await fetchSessionList();
      } catch (error) {
        console.error("Session fetch error:", error);
      }
    };

    fetchSessions();
  }, [user.email, token]);

  // 컴포넌트 언마운트 시 음성 정리
  useEffect(() => {
    return () => {
      if ("speechSynthesis" in window) {
        window.speechSynthesis.cancel();
      }
    };
  }, []);

  // ChatMessage 컴포넌트에 TTS 버튼 추가를 위한 렌더 함수
  const renderMessage = (message) => (
    <div key={message.id} className="flex items-start space-x-2">
      <ChatMessage {...message} />
      {message.type === "bot" && (
        <button
          onClick={() => speak(message.content)}
          className={`p-2 rounded-full ${
            isSpeaking
              ? "bg-red-500 hover:bg-red-600"
              : "bg-gray-200 hover:bg-gray-300"
          }`}
        >
          {isSpeaking ? (
            <VolumeX className="w-4 h-4 text-white" />
          ) : (
            <Volume2 className="w-4 h-4 text-gray-600" />
          )}
        </button>
      )}
    </div>
  );

  return (
    <div className="flex h-full">
      <div className="w-1/4 h-full border-r border-gray-200">
        <ChatHistory
          sessions={sessions}
          onSessionSelect={handleSessionSelect}
          currentSessionId={sessionId}
          onToggleDashboard={handleToggleDashboard}
          showDashboard={showDashboard}
        />
      </div>

      <div className="flex-1 flex flex-col h-full">
        {showDashboard ? (
          <FileDashboard />
        ) : (
          <>
            <div className="flex-1 overflow-y-auto p-4 bg-white">
              {messages.map(renderMessage)}
              {isLoading && <LoadingMessage />}
            </div>

            <div className="border-t border-gray-200 flex items-center">
              <button
                onClick={isListening ? stopListening : startListening}
                className={`p-2 mx-2 rounded-full ${
                  isListening
                    ? "bg-red-500 hover:bg-red-600"
                    : "bg-blue-500 hover:bg-blue-600"
                }`}
              >
                {isListening ? (
                  <MicOff className="w-5 h-5 text-white" />
                ) : (
                  <Mic className="w-5 h-5 text-white" />
                )}
              </button>

              <div className="flex-1">
                <MessageInput
                  onSendMessage={handleMessageSubmit}
                  isLoading={isLoading}
                  transcript={transcript}
                />
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
