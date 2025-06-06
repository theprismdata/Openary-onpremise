import React from "react";
import { useSelector } from "react-redux";

export default function MainLayout({ children }) {
  const { isAuthenticated } = useSelector((state) => state.auth);

  if (!isAuthenticated) {
    return children;
  }

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 px-4 py-3 flex-shrink-0">
        <div className="flex items-center">
          <div className="w-10 h-10 rounded-full bg-[#f8e8d8] flex items-center justify-center mr-3">
            <img
              src="/images/coding-sloth.png"
              alt="OpenAry Logo"
              className="w-8 h-8 object-contain"
            />
          </div>
          <h1 className="text-xl font-bold text-gray-800">OpenAry</h1>
        </div>
      </header>

      {/* Main Content Area */}
      <div className="flex-1 overflow-hidden">
        {children}
      </div>
    </div>
  );
}