// src/components/auth/ProtectedRoute.jsx
import { Navigate, useLocation } from "react-router-dom";
import { useSelector } from "react-redux";

export default function ProtectedRoute({ children }) {
  const { isAuthenticated } = useSelector((state) => state.auth);
  const location = useLocation();

  if (!isAuthenticated) {
    // 로그인 후 원래 가려고 했던 페이지로 리다이렉트하기 위해
    // 현재 위치를 state로 전달
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}
