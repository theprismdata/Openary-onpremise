import React from 'react';

export default function LoadingMessage() {
  return (
    <div className="flex items-center space-x-2 mb-4">
      <div className="bg-gray-100 p-4 rounded-lg">
        <div className="flex items-center">
          <div className="flex space-x-2">
            <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
            <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
            <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
          </div>
          <span className="ml-3 text-gray-600">답변을 생성하고 있습니다...</span>
        </div>
      </div>
    </div>
  );
}