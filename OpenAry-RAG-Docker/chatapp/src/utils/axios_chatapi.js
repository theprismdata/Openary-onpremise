import axios from 'axios';

const isDevelopment = import.meta.env.DEV; // Vite에서 제공하는 환경 변수
console.log("axios_chatapi: isDev");
console.log("axios_chatapi: ", isDevelopment);

const instance = axios.create({
  baseURL: isDevelopment 
    ? 'http://localhost:9000/chatapi'  // 개발 환경
    : '/chatapi',                      // 운영 환경 (nginx proxy 사용)
  headers: {
    'Content-Type': 'application/json',
  },
});

// 요청 인터셉터 - 토큰 추가
instance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// 응답 인터셉터 - 에러 처리
instance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default instance;
