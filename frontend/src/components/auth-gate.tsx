"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";

import { useAuth } from "@/components/auth-provider";

const PUBLIC_PATHS = new Set(["/", "/about", "/login"]);

export function AuthGate({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { isAuthenticated, isLoading } = useAuth();

  useEffect(() => {
    if (isLoading) {
      return;
    }

    if (!PUBLIC_PATHS.has(pathname) && !isAuthenticated) {
      router.replace("/login");
    }
  }, [isAuthenticated, isLoading, pathname, router]);

  if (isLoading) {
    return <div className="auth-loading">LOADING SESSION...</div>;
  }

  if (!PUBLIC_PATHS.has(pathname) && !isAuthenticated) {
    return null;
  }

  return <>{children}</>;
}
