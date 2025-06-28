// src/services/chatService.js
import axios from '../utils/axios_chatapi';

export const sendMessage = async (messageData, token) => {
  const response = await axios.post('/rqa', messageData, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

export const sendStreamingMessage = async (messageData, token) => {
  // Fetch API 사용 (스트리밍 응답을 위해)
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

export const getSessionList = async (email, token) => {
  try {
    console.log('Sending getSessionList request with:', {
      email,
      token: token ? 'Token exists' : 'No token',
      headers: { Authorization: `Bearer ${token}` }
    });
    
    const response = await axios.post('/getsessionlist', { email }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    return response.data;
  } catch (error) {
    console.error('getSessionList error:', {
      status: error.response?.status,
      data: error.response?.data,
      headers: error.config?.headers
    });
    throw error;
  }
};