// src/components/auth/LoginForm.jsx
const DeleteConfirmDialog = ({ isOpen, onClose, onConfirm, email }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
        <h2 className="text-xl font-semibold text-gray-800 mb-4">
          사용자 제거 확인
        </h2>
        <p className="text-gray-600 mb-6">
          정말로 사용자 '{email}'을(를) 제거하시겠습니까? 이 작업은 되돌릴 수
          없습니다.
        </p>
        <div className="flex justify-end space-x-4">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200"
          >
            취소
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700"
          >
            제거
          </button>
        </div>
      </div>
    </div>
  );
};

import { useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate, useLocation } from "react-router-dom";
import { UserPlus, UserX, Lock } from "lucide-react";
import axios_mgmt from "../../utils/axios_mgmt";
import {
  loginUser,
  selectAuthError,
  selectAuthLoading,
} from "../../store/slices/authSlice";

export default function LoginForm() {
  const [formData, setFormData] = useState({
    email: "",
    password: "",
  });
  const [passwordError, setPasswordError] = useState("");
  const [showAddUser, setShowAddUser] = useState(false);
  const [showDeleteUser, setShowDeleteUser] = useState(false);
  const [showChangePassword, setShowChangePassword] = useState(false);
  const [newUserData, setNewUserData] = useState({
    email: "",
    new_passwd: "",
    confirmPassword: "",
  });
  const [deleteUserData, setDeleteUserData] = useState({
    email: "",
    passwd: "",
  });
  const [changePasswordData, setChangePasswordData] = useState({
    email: "",
    passwd: "",
    new_passwd: "",
    confirmNewPassword: "",
  });
  const [addUserMessage, setAddUserMessage] = useState("");
  const [deleteUserMessage, setDeleteUserMessage] = useState("");
  const [changePasswordMessage, setChangePasswordMessage] = useState("");
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  const error = useSelector(selectAuthError);
  const isLoading = useSelector(selectAuthLoading);

  const from = location.state?.from?.pathname || "/chat";

  // showMainForm 추가
  const showMainForm = !showAddUser && !showDeleteUser && !showChangePassword;

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleNewUserChange = (e) => {
    const { name, value } = e.target;
    setNewUserData((prev) => ({
      ...prev,
      [name === "password" ? "new_passwd" : name]: value,
    }));
    setPasswordError("");
  };

  const handleDeleteUserChange = (e) => {
    const { name, value } = e.target;
    setDeleteUserData((prev) => ({
      ...prev,
      [name === "password" ? "passwd" : name]: value,
    }));
  };

  const handleChangePasswordChange = (e) => {
    const { name, value } = e.target;
    setChangePasswordData((prev) => ({
      ...prev,
      [name]: value,
    }));
    setPasswordError("");
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const resultAction = await dispatch(loginUser(formData));
      if (loginUser.fulfilled.match(resultAction)) {
        navigate(from, { replace: true });
      }
    } catch (err) {
      console.error("Login failed:", err);
    }
  };

  const handleAddUser = async (e) => {
    e.preventDefault();

    if (newUserData.new_passwd !== newUserData.confirmPassword) {
      setPasswordError("비밀번호가 일치하지 않습니다.");
      return;
    }

    try {
      const response = await axios_mgmt.post("/add_user", {
        email: newUserData.email,
        new_passwd: newUserData.new_passwd,
      });

      if (response.data.auth && response.data.status === "ok") {
        setAddUserMessage("사용자가 성공적으로 추가되었습니다.");
        setNewUserData({ email: "", new_passwd: "", confirmPassword: "" });
        setTimeout(() => {
          setAddUserMessage("");
          setShowAddUser(false);
        }, 3000);
      }
    } catch (err) {
      setAddUserMessage("사용자 추가 중 오류가 발생했습니다.");
      console.error("Add user failed:", err);
    }
  };

  const handleDeleteUser = async () => {
    try {
      const response = await axios_mgmt.post("/delete_user", deleteUserData);

      if (response.data.status === "ok") {
        setDeleteUserMessage("사용자가 성공적으로 제거되었습니다.");
        setDeleteUserData({ email: "", passwd: "" });
        setShowDeleteConfirm(false);
        setTimeout(() => {
          setDeleteUserMessage("");
          setShowDeleteUser(false);
        }, 3000);
      }
    } catch (err) {
      setDeleteUserMessage("사용자 제거 중 오류가 발생했습니다.");
      setShowDeleteConfirm(false);
      console.error("Delete user failed:", err);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();

    if (
      changePasswordData.new_passwd !== changePasswordData.confirmNewPassword
    ) {
      setPasswordError("새 비밀번호가 일치하지 않습니다.");
      return;
    }

    try {
      const response = await axios_mgmt.post("/update_password", {
        email: changePasswordData.email,
        passwd: changePasswordData.passwd,
        new_passwd: changePasswordData.new_passwd,
      });

      if (response.data.status === "ok") {
        setChangePasswordMessage("비밀번호가 성공적으로 변경되었습니다.");
        setChangePasswordData({
          email: "",
          passwd: "",
          new_passwd: "",
          confirmNewPassword: "",
        });
        setTimeout(() => {
          setChangePasswordMessage("");
          setShowChangePassword(false);
        }, 3000);
      }
    } catch (err) {
      setChangePasswordMessage("비밀번호 변경 중 오류가 발생했습니다.");
      console.error("Password change failed:", err);
    }
  };
  return (
    <div className="min-h-screen flex flex-col justify-center items-end bg-gradient-to-b from-blue-50 to-[#f8e8d8] p-6">
      <div className="w-full max-w-[400px] bg-white rounded-2xl shadow-2xl p-8 mx-auto">
        <div className="flex flex-col items-center mb-8">
          <div className="w-40 h-40 mb-6 rounded-full bg-[#f8e8d8] flex items-center justify-center p-4">
            <img
              src="/images/coding-sloth.png"
              alt="Coding Sloth"
              className="w-32 h-32 object-contain"
            />
          </div>
          <h2 className="text-3xl font-bold text-gray-800 mb-2">
            OpenAry RAG System
          </h2>
          <p className="text-sm text-gray-600">
            나무늘보와 함께 지식을 검색해봐요.
          </p>
          <p className="text-sm text-gray-600">
            GPT-4o, Claude, Gemma를 지원합니다.
          </p>
        </div>

        {/* 로그인 폼 */}
        {showMainForm && (
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-5">
              <div>
                <label
                  htmlFor="email"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  이메일
                </label>
                <div className="relative">
                  <input
                    id="email"
                    name="email"
                    type="email"
                    required
                    value={formData.email}
                    onChange={handleChange}
                    className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ease-in-out"
                    placeholder="이메일"
                  />
                </div>
              </div>

              <div>
                <label
                  htmlFor="password"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  비밀번호
                </label>
                <div className="relative">
                  <input
                    id="password"
                    name="password"
                    type="password"
                    required
                    value={formData.password}
                    onChange={handleChange}
                    className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ease-in-out"
                    placeholder="비밀번호"
                  />
                </div>
              </div>
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4">
                <p className="text-sm font-medium">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading}
              className={`w-full py-3 px-4 rounded-lg text-white text-sm font-medium transition-all duration-200 ease-in-out
                ${
                  isLoading
                    ? "bg-blue-400 cursor-not-allowed"
                    : "bg-blue-600 hover:bg-blue-700 hover:shadow-lg transform hover:-translate-y-0.5"
                }`}
            >
              {isLoading ? (
                <span className="flex items-center justify-center">
                  <svg
                    className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    ></circle>
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    ></path>
                  </svg>
                  로그인 중...
                </span>
              ) : (
                "로그인"
              )}
            </button>
          </form>
        )}

        {/* 사용자 관리 메뉴 - 항상 표시 */}
        <div className="mt-6 flex justify-between flex-wrap gap-4">
          <button
            onClick={() => {
              setShowAddUser(true);
              setShowDeleteUser(false);
              setShowChangePassword(false);
            }}
            className="flex items-center gap-2 text-blue-600 hover:text-blue-700 text-sm font-medium"
          >
            <UserPlus size={16} />
            무료 회원 가입
          </button>
          <button
            onClick={() => {
              setShowChangePassword(true);
              setShowAddUser(false);
              setShowDeleteUser(false);
            }}
            className="flex items-center gap-2 text-yellow-600 hover:text-yellow-700 text-sm font-medium"
          >
            <Lock size={16} />
            비밀번호 변경
          </button>
          <button
            onClick={() => {
              setShowDeleteUser(true);
              setShowAddUser(false);
              setShowChangePassword(false);
            }}
            className="flex items-center gap-2 text-red-600 hover:text-red-700 text-sm font-medium"
          >
            <UserX size={16} />
            회원 탈퇴
          </button>
        </div>

        {/* 사용자 추가 폼 */}
        {showAddUser && (
          <form onSubmit={handleAddUser} className="mt-6 space-y-6">
            <div className="space-y-5">
              <div>
                <label
                  htmlFor="newEmail"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  새 회원 이메일
                </label>
                <input
                  id="newEmail"
                  name="email"
                  type="email"
                  required
                  value={newUserData.email}
                  onChange={handleNewUserChange}
                  className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ease-in-out"
                  placeholder="새 이메일"
                />
              </div>

              <div>
                <label
                  htmlFor="newPassword"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  새 비밀번호
                </label>
                <input
                  id="newPassword"
                  name="password"
                  type="password"
                  required
                  value={newUserData.new_passwd}
                  onChange={handleNewUserChange}
                  className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ease-in-out"
                  placeholder="새 비밀번호"
                />
              </div>

              <div>
                <label
                  htmlFor="confirmPassword"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  비밀번호 확인
                </label>
                <input
                  id="confirmPassword"
                  name="confirmPassword"
                  type="password"
                  required
                  value={newUserData.confirmPassword}
                  onChange={handleNewUserChange}
                  className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ease-in-out"
                  placeholder="비밀번호 확인"
                />
              </div>
            </div>

            <div className="flex space-x-4">
              <button
                type="button"
                onClick={() => {
                  setShowAddUser(false);
                  setNewUserData({
                    email: "",
                    new_passwd: "",
                    confirmPassword: "",
                  });
                }}
                className="flex-1 py-3 px-4 rounded-lg text-gray-700 text-sm font-medium bg-gray-100 hover:bg-gray-200 transition-all duration-200 ease-in-out"
              >
                취소
              </button>
              <button
                type="submit"
                className="flex-1 py-3 px-4 rounded-lg text-white text-sm font-medium bg-blue-600 hover:bg-blue-700 hover:shadow-lg transform hover:-translate-y-0.5 transition-all duration-200 ease-in-out"
              >
                사용자 추가
              </button>
            </div>
          </form>
        )}

        {/* 비밀번호 변경 폼 */}
        {showChangePassword && (
          <form onSubmit={handleChangePassword} className="mt-6 space-y-6">
            <div className="space-y-5">
              <div>
                <label
                  htmlFor="changeEmail"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  이메일
                </label>
                <input
                  id="changeEmail"
                  name="email"
                  type="email"
                  required
                  value={changePasswordData.email}
                  onChange={handleChangePasswordChange}
                  className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ease-in-out"
                  placeholder="이메일"
                />
              </div>

              <div>
                <label
                  htmlFor="currentPassword"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  현재 비밀번호
                </label>
                <input
                  id="currentPassword"
                  name="passwd"
                  type="password"
                  required
                  value={changePasswordData.passwd}
                  onChange={handleChangePasswordChange}
                  className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ease-in-out"
                  placeholder="현재 비밀번호"
                />
              </div>

              <div>
                <label
                  htmlFor="newPassword"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  새 비밀번호
                </label>
                <input
                  id="newPassword"
                  name="new_passwd"
                  type="password"
                  required
                  value={changePasswordData.new_passwd}
                  onChange={handleChangePasswordChange}
                  className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ease-in-out"
                  placeholder="새 비밀번호"
                />
              </div>

              <div>
                <label
                  htmlFor="confirmNewPassword"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  새 비밀번호 확인
                </label>
                <input
                  id="confirmNewPassword"
                  name="confirmNewPassword"
                  type="password"
                  required
                  value={changePasswordData.confirmNewPassword}
                  onChange={handleChangePasswordChange}
                  className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ease-in-out"
                  placeholder="새 비밀번호 확인"
                />
              </div>

              {passwordError && (
                <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4">
                  <p className="text-sm font-medium">{passwordError}</p>
                </div>
              )}
            </div>

            <div className="flex space-x-4">
              <button
                type="button"
                onClick={() => {
                  setShowChangePassword(false);
                  setChangePasswordData({
                    email: "",
                    passwd: "",
                    new_passwd: "",
                    confirmNewPassword: "",
                  });
                }}
                className="flex-1 py-3 px-4 rounded-lg text-gray-700 text-sm font-medium bg-gray-100 hover:bg-gray-200 transition-all duration-200 ease-in-out"
              >
                취소
              </button>
              <button
                type="submit"
                className="flex-1 py-3 px-4 rounded-lg text-white text-sm font-medium bg-yellow-600 hover:bg-yellow-700 hover:shadow-lg transform hover:-translate-y-0.5 transition-all duration-200 ease-in-out"
              >
                비밀번호 변경
              </button>
            </div>
          </form>
        )}

        {/* 사용자 제거 폼 */}
        {showDeleteUser && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setShowDeleteConfirm(true);
            }}
            className="mt-6 space-y-6"
          >
            <div className="space-y-5">
              <div>
                <label
                  htmlFor="deleteEmail"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  제거할 사용자 이메일
                </label>
                <input
                  id="deleteEmail"
                  name="email"
                  type="email"
                  required
                  value={deleteUserData.email}
                  onChange={handleDeleteUserChange}
                  className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ease-in-out"
                  placeholder="이메일"
                />
              </div>

              <div>
                <label
                  htmlFor="deletePassword"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  비밀번호
                </label>
                <input
                  id="deletePassword"
                  name="password"
                  type="password"
                  required
                  value={deleteUserData.passwd}
                  onChange={handleDeleteUserChange}
                  className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 ease-in-out"
                  placeholder="비밀번호"
                />
              </div>
            </div>

            <div className="flex space-x-4">
              <button
                type="button"
                onClick={() => {
                  setShowDeleteUser(false);
                  setDeleteUserData({ email: "", passwd: "" });
                }}
                className="flex-1 py-3 px-4 rounded-lg text-gray-700 text-sm font-medium bg-gray-100 hover:bg-gray-200 transition-all duration-200 ease-in-out"
              >
                취소
              </button>
              <button
                type="submit"
                className="flex-1 py-3 px-4 rounded-lg text-white text-sm font-medium bg-red-600 hover:bg-red-700 hover:shadow-lg transform hover:-translate-y-0.5 transition-all duration-200 ease-in-out"
              >
                사용자 제거
              </button>
            </div>
          </form>
        )}
        {/* 메시지 표시 */}
        {(addUserMessage || deleteUserMessage || changePasswordMessage) && (
          <div
            className={`mt-4 p-4 rounded-lg ${
              (
                addUserMessage ||
                deleteUserMessage ||
                changePasswordMessage
              ).includes("성공")
                ? "bg-green-50 border border-green-200 text-green-700"
                : "bg-red-50 border border-red-200 text-red-700"
            }`}
          >
            <p className="text-sm font-medium">
              {addUserMessage || deleteUserMessage || changePasswordMessage}
            </p>
          </div>
        )}

        <DeleteConfirmDialog
          isOpen={showDeleteConfirm}
          onClose={() => setShowDeleteConfirm(false)}
          onConfirm={handleDeleteUser}
          email={deleteUserData.email}
        />
      </div>

      {/* Contributor 섹션 */}
      <div className="absolute bottom-4 right-6 text-right">
        <p className="text-xs font-medium text-gray-400 mb-1">
          OpenAry Contributer
        </p>
        <div className="space-y-0.5">
          <p className="text-xs text-gray-400">theprismdata@gmail.com</p>
          <p className="text-xs text-gray-400">tnrud4685@gmail.com</p>
          <p className="text-xs text-gray-400">armyost1@gmail.com</p>
          <p className="text-xs text-gray-400">ljs9643@gmail.com</p>
        </div>
      </div>
    </div>
  );
}
