"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
  type ReactNode,
} from "react";

export type AuthUser = {
  email: string;
  name: string;
};

type AuthContextValue = {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
};

const AUTH_KEY = "verity-auth-session";
const AUTH_CHANGE_EVENT = "verity-auth-change";
const LOADING_SESSION = "__WEBVERITY_SESSION_LOADING__";
const AuthContext = createContext<AuthContextValue | undefined>(undefined);

function isAuthUser(value: unknown): value is AuthUser {
  return (
    typeof value === "object" &&
    value !== null &&
    "email" in value &&
    typeof value.email === "string" &&
    "name" in value &&
    typeof value.name === "string"
  );
}

function readStoredSession(): string | null {
  try {
    return window.localStorage.getItem(AUTH_KEY);
  } catch {
    return null;
  }
}

function subscribeToSession(onChange: () => void) {
  window.addEventListener("storage", onChange);
  window.addEventListener(AUTH_CHANGE_EVENT, onChange);
  return () => {
    window.removeEventListener("storage", onChange);
    window.removeEventListener(AUTH_CHANGE_EVENT, onChange);
  };
}

function parseUser(session: string | null): AuthUser | null {
  if (!session || session === LOADING_SESSION) {
    return null;
  }

  try {
    const parsed: unknown = JSON.parse(session);
    return isAuthUser(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function normalizeName(email: string) {
  const localPart = email.split("@")[0] ?? email;
  return localPart
    .replace(/[._-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const session = useSyncExternalStore(
    subscribeToSession,
    readStoredSession,
    () => LOADING_SESSION,
  );
  const user = useMemo(() => parseUser(session), [session]);
  const isLoading = session === LOADING_SESSION;

  useEffect(() => {
    if (session === LOADING_SESSION || !session || user) {
      return;
    }

    window.localStorage.removeItem(AUTH_KEY);
  }, [session, user]);

  const login = useCallback(async (email: string, password: string) => {
    const trimmedEmail = email.trim();
    const trimmedPassword = password.trim();

    if (!trimmedEmail || !trimmedPassword) {
      throw new Error("Email and password are required.");
    }

    const validEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail);
    if (!validEmail) {
      throw new Error("Enter a valid email address.");
    }

    if (trimmedPassword.length < 6) {
      throw new Error("Password must be at least 6 characters long.");
    }

    const nextUser: AuthUser = {
      email: trimmedEmail,
      name: normalizeName(trimmedEmail) || "Operator",
    };

    window.localStorage.setItem(AUTH_KEY, JSON.stringify(nextUser));
    window.dispatchEvent(new Event(AUTH_CHANGE_EVENT));
  }, []);

  const logout = useCallback(() => {
    window.localStorage.removeItem(AUTH_KEY);
    window.dispatchEvent(new Event(AUTH_CHANGE_EVENT));
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isAuthenticated: !!user,
      isLoading,
      login,
      logout,
    }),
    [isLoading, login, logout, user],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return context;
}
