import React, { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { logout } from "../../store/slices/authSlice";
import axios from "../../utils/axios_chatapi";
import { X, MessageCircle, FileText, Paperclip } from "lucide-react";

export default function ChatHistory({
  sessions,
  onSessionSelect,
  currentSessionId,
  onToggleDashboard,
  showDashboard,
}) {
  const dispatch = useDispatch();
  const { user, token } = useSelector((state) => state.auth);
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchDocuments = async () => {
      if (showDashboard) {
        setLoading(true);
        setError(null);
        try {
          const response = await axios.post(
            "/getdocs",
            {
              email: user.email,
            },
            {
              headers: {
                Authorization: `Bearer ${token}`,
              },
            }
          );
          setDocuments(response.data.fileinfo || []);
        } catch (err) {
          setError("문서 목록을 불러오는데 실패했습니다.");
          console.error("Error fetching documents:", err);
        } finally {
          setLoading(false);
        }
      }
    };

    fetchDocuments();
  }, [showDashboard, user.email, token]);

  const handleFileSelect = (event) => {
    const files = Array.from(event.target.files);
    setSelectedFiles((prev) => [...prev, ...files]);
    setUploadStatus(null);
    event.target.value = "";
  };

  const handleRemoveFile = (indexToRemove) => {
    setSelectedFiles((prev) =>
      prev.filter((_, index) => index !== indexToRemove)
    );
  };

  const handleUpload = async () => {
    if (!selectedFiles.length) {
      setUploadStatus({
        type: "error",
        message: "선택된 파일이 없습니다.",
      });
      return;
    }

    setUploading(true);
    setUploadStatus(null);

    const formData = new FormData();
    formData.append("email", user.email);

    selectedFiles.forEach((file) => {
      formData.append("upload_files", file);
    });

    try {
      const response = await axios({
        method: "post",
        url: "/files/upload/",
        data: formData,
        headers: {
          "Content-Type": "multipart/form-data",
          Authorization: `Bearer ${token}`,
        },
      });

      const result = response.data;
      setUploadStatus({
        type: "success",
        message: `${result.total_files}개 파일 업로드 완료 (총 ${(
          result.total_size / 1024
        ).toFixed(1)}KB)`,
      });
      setSelectedFiles([]);
    } catch (error) {
      console.error("Upload error:", error);
      setUploadStatus({
        type: "error",
        message: "파일 업로드 중 오류가 발생했습니다.",
      });
    } finally {
      setUploading(false);
      setTimeout(() => setUploadStatus(null), 5000);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  };

  return (
    <div className="h-full bg-gray-50 flex flex-col">
      <div className="mb-3 p-4">
        <div className="relative">
          <select
            value={showDashboard ? "docs" : "chat"}
            onChange={(e) => onToggleDashboard(e.target.value === "docs")}
            className="w-full p-3 text-lg font-bold bg-white border border-gray-200 rounded-lg appearance-none cursor-pointer hover:border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="chat">채팅 히스토리</option>
            <option value="docs">문서 목록</option>
          </select>
          <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
            {showDashboard ? (
              <FileText className="w-5 h-5 text-gray-500" />
            ) : (
              <MessageCircle className="w-5 h-5 text-gray-500" />
            )}
          </div>
        </div>
      </div>

      <div className="flex-1 p-4 overflow-y-auto">
        {showDashboard ? (
          <div className="space-y-4">
            <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
              {loading ? (
                <div className="flex items-center justify-center py-4">
                  <svg
                    className="animate-spin h-5 w-5 text-blue-600"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    ></circle>
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    ></path>
                  </svg>
                  <span className="ml-2">문서 목록을 불러오는 중...</span>
                </div>
              ) : error ? (
                <div className="text-red-600 text-center py-4">{error}</div>
              ) : (
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <span className="bg-blue-100 text-blue-800 text-sm font-medium px-3 py-1 rounded-full">
                      총 {documents.length}개
                    </span>
                  </div>
                  {documents.length === 0 ? (
                    <p className="text-gray-500 text-center py-4">
                      업로드된 문서가 없습니다.
                    </p>
                  ) : (
                    <ul className="space-y-2">
                      {documents.map((doc, index) => (
                        <li
                          key={index}
                          className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors duration-200"
                        >
                          <FileText className="w-5 h-5 text-gray-400 flex-shrink-0" />
                          <span className="text-sm text-gray-900 truncate">
                            {doc.filename}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          </div>
        ) : (
          <>
            <button
              onClick={() => onSessionSelect(0)}
              className="w-full text-left p-3 mb-4 rounded-lg flex items-center space-x-3 bg-blue-50 hover:bg-blue-100 text-blue-700 transition-colors duration-200"
            >
              <MessageCircle size={18} className="flex-shrink-0" />
              <span className="font-medium">New Chat</span>
            </button>

            <div className="space-y-2">
              {sessions.map((session) => {
                const [sessionId, title] = Object.entries(session)[0];
                return (
                  <button
                    key={sessionId}
                    onClick={() => onSessionSelect(sessionId)}
                    className={`w-full text-left p-3 rounded-lg flex items-center space-x-3 ${
                      currentSessionId === sessionId
                        ? "bg-blue-100 text-blue-800"
                        : "hover:bg-gray-100"
                    }`}
                  >
                    <MessageCircle
                      size={18}
                      className={`flex-shrink-0 ${
                        currentSessionId === sessionId
                          ? "text-blue-800"
                          : "text-gray-500"
                      }`}
                    />
                    <span className="truncate">{title}</span>
                  </button>
                );
              })}
            </div>
          </>
        )}
      </div>

      <div className="border-t border-gray-200 p-4">
        <div className="mb-4">
          <label className="block">
            <div className="relative">
              {/* 파일 선택 버튼 디자인 변경 및 클립 아이콘 추가 */}
              <div className="relative flex items-center w-full">
                <div className="relative overflow-hidden flex-1">
                  <div className="flex items-center p-2 border border-gray-200 bg-white rounded-lg">
                    <Paperclip className="h-5 w-5 text-blue-600 mr-2" />
                    <span className="text-sm text-gray-700">
                      {selectedFiles.length === 0
                        ? "파일을 선택하세요"
                        : `${selectedFiles.length}개 파일 선택됨`}
                    </span>
                  </div>
                  <input
                    id="file-input"
                    type="file"
                    multiple
                    onChange={handleFileSelect}
                    disabled={uploading}
                    className="absolute inset-0 opacity-0 w-full cursor-pointer"
                  />
                </div>
              </div>
            </div>
          </label>
        </div>

        {selectedFiles.length > 0 && (
          <div className="mb-4">
            <p className="text-sm font-medium text-gray-700 mb-2">
              선택된 파일 ({selectedFiles.length}개):
            </p>
            <ul className="text-sm text-gray-600 space-y-2">
              {selectedFiles.map((file, index) => (
                <li
                  key={index}
                  className="flex items-center justify-between bg-white p-2 rounded-lg border border-gray-200"
                >
                  <div className="flex-1 min-w-0 mr-2">
                    <p className="truncate">{file.name}</p>
                    <p className="text-xs text-gray-500">
                      {formatFileSize(file.size)}
                    </p>
                  </div>
                  <button
                    onClick={() => handleRemoveFile(index)}
                    className="flex items-center justify-center p-1 hover:bg-gray-100 rounded-full text-gray-500 hover:text-red-600 transition-colors duration-200"
                    title="파일 삭제"
                  >
                    <X size={16} />
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}

        <button
          onClick={handleUpload}
          disabled={uploading || selectedFiles.length === 0}
          className={`w-full py-2 px-4 rounded-lg text-white text-sm font-medium
            ${
              uploading || selectedFiles.length === 0
                ? "bg-gray-400 cursor-not-allowed"
                : "bg-blue-600 hover:bg-blue-700 transition-colors duration-200"
            }
          `}
        >
          {uploading ? (
            <span className="flex items-center justify-center">
              <svg
                className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                ></circle>
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                ></path>
              </svg>
              파일 전송 중...
            </span>
          ) : (
            "파일 전송"
          )}
        </button>

        {uploadStatus && (
          <div
            className={`mt-4 p-3 rounded-lg text-sm ${
              uploadStatus.type === "success"
                ? "bg-green-50 text-green-700"
                : "bg-red-50 text-red-700"
            }`}
          >
            {uploadStatus.message}
          </div>
        )}
      </div>

      <div className="border-t border-gray-200 p-4 bg-gray-50">
        <div className="mb-3">
          <p className="text-sm text-gray-600">로그인 사용자:</p>
          <p className="text-sm font-medium text-gray-800">{user?.email}</p>
        </div>
        <button
          onClick={() => {
            sessionStorage.removeItem("dashboardView");
            dispatch(logout());
          }}
          className="w-full py-2 px-4 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors duration-200"
        >
          로그아웃
        </button>
      </div>
    </div>
  );
}
