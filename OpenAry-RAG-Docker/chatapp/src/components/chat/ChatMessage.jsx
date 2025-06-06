import React, { useState } from "react";
import { marked } from "marked";
import DOMPurify from "dompurify";
import {
  ChevronDown,
  ChevronUp,
  BookOpen,
  Search,
  ExternalLink,
  FileText,
} from "lucide-react";

export default function ChatMessage({
  type,
  content = "",
  sources = [],
  searchResults = [],
  isComplete = type !== "bot",
}) {
  const [showSources, setShowSources] = useState(false);
  const [showSearchResults, setShowSearchResults] = useState(false);

  const renderMarkdown = (text) => {
    if (!text) return "";

    try {
      // SYSTEM, HUMAN 레이블 제거
      let cleanedText = text.replace(/^(System|Human):\s*/gm, "");

      // marked 옵션 설정
      marked.setOptions({
        breaks: true, // 줄바꿈 활성화
        gfm: true, // GitHub Flavored Markdown 활성화
        headerIds: false, // 헤더 ID 생성 비활성화
      });

      // 마크다운 파싱
      const rawHtml = marked.parse(cleanedText);

      // 보안 처리
      const cleanHtml = DOMPurify.sanitize(rawHtml, {
        USE_PROFILES: { html: true }, // HTML 허용
        ADD_ATTR: ["target"], // 외부 링크를 위한 target 속성 허용
      });

      return cleanHtml;
    } catch (error) {
      console.error("Markdown rendering error:", error);
      // 파싱 실패 시 기본 텍스트 표시 (여기서도 레이블 제거)
      return text
        .replace(/^(System|Human):\s*/gm, "")
        .replace(/\n/g, "<br>")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    }
  };

  // URL 검증 함수
  const isValidUrl = (url) => {
    try {
      new URL(url);
      return true;
    } catch (e) {
      return false;
    }
  };

  // 소스 버튼은 소스가 있고 Bot 메시지일 때만 표시
  const hasSourcesData = type === "bot" && sources && sources.length > 0;

  // 검색 결과 버튼은 검색 결과가 있고 Bot 메시지일 때만 표시
  const hasSearchResultsData =
    type === "bot" && searchResults && searchResults.length > 0;

  // 소스에서 URL 추출
  const getSourceUrl = (source) => {
    // URL 필드가 여러 이름으로 존재할 수 있음
    const urlField =
      source.url || source.link || source.source_url || source.sourceUrl;

    if (urlField && isValidUrl(urlField)) {
      return urlField;
    }

    return null;
  };

  // 문서 종류에 따른 아이콘 선택
  const getDocumentIcon = (filename) => {
    if (!filename) return <FileText size={14} />;

    const extension = filename.split(".").pop().toLowerCase();

    switch (extension) {
      case "pdf":
        return <FileText size={14} />;
      case "doc":
      case "docx":
        return <FileText size={14} />;
      default:
        return <FileText size={14} />;
    }
  };

  return (
    <div
      className={`mb-4 ${type === "user" ? "text-right" : "text-left"} w-full`}
    >
      <div
        className={`inline-block p-4 rounded-lg ${
          type === "user"
            ? "bg-blue-500 text-white"
            : "bg-gray-100 text-gray-800"
        }`}
      >
        <div className="prose dark:prose-invert max-w-none">
          <div
            dangerouslySetInnerHTML={{
              __html: renderMarkdown(content),
            }}
          />
        </div>
      </div>

      {/* 소스 및 검색결과 표시 버튼 영역 */}
      {type === "bot" && (
        <div className="mt-2 flex flex-wrap gap-2">
          {hasSourcesData && (
            <button
              onClick={() => setShowSources(!showSources)}
              className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-800 transition-colors py-1 px-2 rounded-md bg-blue-50 hover:bg-blue-100"
            >
              <BookOpen size={14} />
              {showSources ? "소스 숨기기" : `소스 보기 (${sources.length})`}
              {showSources ? (
                <ChevronUp size={14} />
              ) : (
                <ChevronDown size={14} />
              )}
            </button>
          )}

          {hasSearchResultsData && (
            <button
              onClick={() => setShowSearchResults(!showSearchResults)}
              className="flex items-center gap-1 text-xs text-green-600 hover:text-green-800 transition-colors py-1 px-2 rounded-md bg-green-50 hover:bg-green-100"
            >
              <Search size={14} />
              {showSearchResults
                ? "검색결과 숨기기"
                : `검색결과 보기 (${searchResults.length})`}
              {showSearchResults ? (
                <ChevronUp size={14} />
              ) : (
                <ChevronDown size={14} />
              )}
            </button>
          )}
        </div>
      )}

      {/* 소스 목록 표시 영역 */}
      {showSources && hasSourcesData && (
        <div className="mt-2 p-3 bg-blue-50 rounded-lg border border-blue-100 text-sm">
          <h4 className="font-medium text-blue-800 mb-2 flex items-center gap-1">
            <BookOpen size={16} />
            참고 소스
          </h4>
          <ul className="space-y-3">
            {sources.map((source, index) => {
              const sourceUrl = getSourceUrl(source);
              return (
                <li key={index} className="text-gray-700">
                  <div className="flex items-start gap-2">
                    <span className="bg-blue-100 text-blue-800 rounded-full w-5 h-5 flex items-center justify-center flex-shrink-0 mt-0.5">
                      {index + 1}
                    </span>
                    <div className="flex-1">
                      <div className="flex items-start justify-between">
                        <div className="flex items-center gap-1">
                          {getDocumentIcon(source.filename)}
                          <p className="font-medium">
                            {/* {source.filename ||
                              source.title ||
                              "문서 이름 없음"}
                               */}
                            {source}
                          </p>
                        </div>
                        {sourceUrl && (
                          <a
                            href={sourceUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-600 hover:text-blue-800 flex items-center ml-2"
                            title="소스 열기"
                          >
                            <ExternalLink size={14} />
                          </a>
                        )}
                      </div>
                      {source.text && (
                        <p className="mt-1 text-gray-600 text-xs rounded bg-white p-2 border border-blue-100">
                          {source.text}
                        </p>
                      )}
                      <div className="flex flex-wrap gap-3 mt-1 text-xs text-gray-500">
                        {source.page !== undefined && (
                          <span>페이지: {source.page}</span>
                        )}
                        {source.chunk !== undefined && (
                          <span>청크: {source.chunk}</span>
                        )}
                        {source.score !== undefined && (
                          <span>
                            관련도: {(source.score * 100).toFixed(1)}%
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {/* 검색 결과 목록 표시 영역 */}
      {showSearchResults && hasSearchResultsData && (
        <div className="mt-2 p-3 bg-green-50 rounded-lg border border-green-100 text-sm">
          <h4 className="font-medium text-green-800 mb-2 flex items-center gap-1">
            <Search size={16} />
            검색 결과
          </h4>
          <ul className="space-y-3">
            {searchResults.map((result, index) => {
              const resultUrl = result.url || result.link;
              return (
                <li key={index} className="text-gray-700">
                  <div className="flex items-start gap-2">
                    <span className="bg-green-100 text-green-800 rounded-full w-5 h-5 flex items-center justify-center flex-shrink-0 mt-0.5">
                      {index + 1}
                    </span>
                    <div className="flex-1">
                      <div className="flex items-start justify-between">
                        <p className="font-medium">
                          {result.title || result.filename || "제목 없음"}
                        </p>
                        {resultUrl && isValidUrl(resultUrl) && (
                          <a
                            href={resultUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-green-600 hover:text-green-800 flex items-center ml-2"
                            title="검색 결과 열기"
                          >
                            <ExternalLink size={14} />
                          </a>
                        )}
                      </div>
                      {result.context && (
                        <p className="mt-1 text-gray-600 text-xs rounded bg-white p-2 border border-green-100">
                          {result.context}
                        </p>
                      )}
                      <div className="flex flex-wrap gap-3 mt-1 text-xs text-gray-500">
                        {result.score !== undefined && (
                          <span>
                            관련도: {(result.score * 100).toFixed(1)}%
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
