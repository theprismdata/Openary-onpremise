import axios from 'axios';

const isDevelopment = import.meta.env.DEV; // Vite에서 제공하는 환경 변수
const instance = axios.create({
  baseURL: isDevelopment 
    ? 'http://localhost:9001/mgmt'  // 개발 환경
    : '/mgmt',                      // 운영 환경 (nginx proxy 사용)
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

export default instance;
