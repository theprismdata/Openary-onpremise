import { createSlice } from "@reduxjs/toolkit";

const initialState = {
  messages: [],
  currentSession: null,
  sessions: [],
  loading: false,
  error: null,
};

const chatSlice = createSlice({
  name: "chat",
  initialState,
  reducers: {
    setMessages: (state, action) => {
      state.messages = action.payload;
    },
    addMessage: (state, action) => {
      state.messages.push(action.payload);
    },
    setSessions: (state, action) => {
      state.sessions = action.payload;
    },
    setCurrentSession: (state, action) => {
      state.currentSession = action.payload;
    },
    setLoading: (state, action) => {
      state.loading = action.payload;
    },
    setError: (state, action) => {
      state.error = action.payload;
    },
  },
});

export const {
  setMessages,
  addMessage,
  setSessions,
  setCurrentSession,
  setLoading,
  setError,
} = chatSlice.actions;

export default chatSlice.reducer;
