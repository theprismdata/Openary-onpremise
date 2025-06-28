// src/App.jsx
import { useEffect } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { setCredentials } from "./store/slices/authSlice";
import LoginForm from "./components/auth/LoginForm";
import ProtectedRoute from "./components/auth/ProtectedRoute";
import ChatWindow from "./components/chat/ChatWindow";
import MainLayout from "./components/layout/MainLayout";
import { getStoredAuth } from "./services/authService";

export default function App() {
  const dispatch = useDispatch();
  const { isAuthenticated } = useSelector((state) => state.auth);

  useEffect(() => {
    // 페이지 새로고침 시 로컬 스토리지에서 인증 정보 복구
    const { token, user } = getStoredAuth();
    if (token && user) {
      dispatch(setCredentials({ token, user }));
    }
  }, [dispatch]);

  return (
    <Router>
      <MainLayout>
        <Routes>
          {/* 로그인 상태일 때는 /login으로 접근 시 /chat으로 리다이렉트 */}
          <Route
            path="/login"
            element={
              isAuthenticated ? <Navigate to="/chat" replace /> : <LoginForm />
            }
          />

          {/* 채팅 페이지는 인증된 사용자만 접근 가능 */}
          <Route
            path="/chat"
            element={
              <ProtectedRoute>
                <ChatWindow />
              </ProtectedRoute>
            }
          />

          {/* 루트 경로로 접근 시 */}
          <Route
            path="/"
            element={
              isAuthenticated ? (
                <Navigate to="/chat" replace />
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />

          {/* 404 페이지 - 없는 경로로 접근 시 */}
          <Route
            path="*"
            element={
              <div className="min-h-screen flex items-center justify-center">
                <div className="text-center">
                  <h1 className="text-4xl font-bold text-gray-800 mb-4">404</h1>
                  <p className="text-gray-600 mb-4">
                    페이지를 찾을 수 없습니다.
                  </p>
                  <button
                    onClick={() => navigate("/")}
                    className="text-blue-500 hover:text-blue-600"
                  >
                    홈으로 돌아가기
                  </button>
                </div>
              </div>
            }
          />
        </Routes>
      </MainLayout>
    </Router>
  );
}
