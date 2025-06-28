// src/services/authService.js
import axios from '../utils/axios_chatapi';

export const loginUser = async (credentials) => {
  try {
    const response = await axios.post('/login', credentials);
    if (response.data.token) {
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify({ email: credentials.email }));
    }
    return response.data;
  } catch (error) {
    // API 에러 처리
    if (error.response) {
      throw new Error(error.response.data.detail || 'Login failed');
    }
    throw new Error('Network error occurred');
  }
};

export const logout = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
};

export const getStoredAuth = () => {
  const token = localStorage.getItem('token');
  let user = null;
  try {
    user = JSON.parse(localStorage.getItem('user'));
  } catch (e) {
    // localStorage에 저장된 user 데이터가 유효하지 않을 경우
    localStorage.removeItem('user');
  }
  return { token, user };
};