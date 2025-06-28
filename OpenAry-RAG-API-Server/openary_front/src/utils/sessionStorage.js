export const setSessionData = (key, value) => {
    try {
      sessionStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.error('Error saving to sessionStorage:', error);
    }
  };
  
  export const getSessionData = (key) => {
    try {
      const item = sessionStorage.getItem(key);
      return item ? JSON.parse(item) : null;
    } catch (error) {
      console.error('Error reading from sessionStorage:', error);
      return null;
    }
  };
  
  export const removeSessionData = (key) => {
    try {
      sessionStorage.removeItem(key);
    } catch (error) {
      console.error('Error removing from sessionStorage:', error);
    }
  };