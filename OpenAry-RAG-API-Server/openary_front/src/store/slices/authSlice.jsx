// src/store/slices/authSlice.js
import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import { loginUser as loginUserApi } from "../../services/authService";

// 비동기 로그인 액션
export const loginUser = createAsyncThunk(
  "auth/login",
  async (credentials, { rejectWithValue }) => {
    try {
      const response = await loginUserApi(credentials);
      return {
        user: { email: credentials.email },
        token: response.token,
      };
    } catch (error) {
      return rejectWithValue(error.response?.data || "로그인에 실패했습니다.");
    }
  }
);

const initialState = {
  user: null,
  token: null,
  isAuthenticated: false,
  loading: false,
  error: null,
  lastLoginAttempt: null,
};

const authSlice = createSlice({
  name: "auth",
  initialState,
  reducers: {
    setCredentials: (state, action) => {
      const { user, token } = action.payload;
      state.user = user;
      state.token = token;
      state.isAuthenticated = true;
      state.error = null;
    },
    logout: (state) => {
      state.user = null;
      state.token = null;
      state.isAuthenticated = false;
      state.error = null;
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      sessionStorage.removeItem("dashboardView"); // 추가
    },
    clearError: (state) => {
      state.error = null;
    },
    updateUser: (state, action) => {
      state.user = { ...state.user, ...action.payload };
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(loginUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loginUser.fulfilled, (state, action) => {
        state.loading = false;
        state.isAuthenticated = true;
        state.user = action.payload.user;
        state.token = action.payload.token;
        state.lastLoginAttempt = new Date().toISOString();
        localStorage.setItem("token", action.payload.token);
        localStorage.setItem("user", JSON.stringify(action.payload.user));
      })
      .addCase(loginUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload || "로그인에 실패했습니다.";
        state.isAuthenticated = false;
      });
  },
});

// Actions
export const { setCredentials, logout, clearError, updateUser } =
  authSlice.actions;

// Selectors
export const selectAuthError = (state) => state.auth.error;
export const selectAuthLoading = (state) => state.auth.loading;
export const selectIsAuthenticated = (state) => state.auth.isAuthenticated;
export const selectUser = (state) => state.auth.user;
export const selectToken = (state) => state.auth.token;
export const selectLastLoginAttempt = (state) => state.auth.lastLoginAttempt;

// Reducer
export default authSlice.reducer;
