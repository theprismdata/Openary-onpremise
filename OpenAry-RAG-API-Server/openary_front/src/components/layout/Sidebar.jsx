import React from "react";
import { useDispatch, useSelector } from "react-redux";
import { logout } from "../../store/slices/authSlice";

export default function Sidebar() {
  const dispatch = useDispatch();
  const { user } = useSelector((state) => state.auth);

  return (
    <div className="w-64 bg-gray-800 text-white p-4">
      <div className="mb-8">
        <h1 className="text-xl font-bold">OpenAry</h1>
      </div>
      <div className="mb-4">
        <p className="text-sm text-gray-400">로그인 사용자:</p>
        <p className="text-sm">{user?.email}</p>
      </div>
      <button
        onClick={() => dispatch(logout())}
        className="w-full py-2 px-4 bg-red-600 text-white rounded hover:bg-red-700"
      >
        로그아웃
      </button>
    </div>
  );
}
