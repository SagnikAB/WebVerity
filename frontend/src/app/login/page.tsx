"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight, ShieldCheck } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";

import { useAuth } from "@/components/auth-provider";

export default function LoginPage() {
  const router = useRouter();
  const { login, isAuthenticated } = useAuth();
  const [email, setEmail] = useState("admin@verity.local");
  const [password, setPassword] = useState("verity123");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  useEffect(() => {
    if (isAuthenticated) {
      router.replace("/dashboard");
    }
  }, [isAuthenticated, router]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    try {
      setPending(true);
      await login(email, password);
      router.push("/dashboard");
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Login failed.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-panel">
        <div className="auth-brand">
          <span className="brand-mark">✦</span>
          <span>WEBVERITY</span>
        </div>

        <div className="auth-copy">
          <p className="eyebrow">LOCAL DEMO SESSION</p>
          <h1>DEMO SIGN IN</h1>
          <p className="subtitle">
            This prototype stores a session in this browser only. It does not verify identities or
            protect backend APIs; do not use it as production authentication.
          </p>
        </div>

        <form onSubmit={onSubmit} className="auth-form">
          <label>
            <span>Email</span>
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="name@company.com"
              autoComplete="email"
            />
          </label>

          <label>
            <span>Password</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
            />
          </label>

          {error ? <p className="auth-error">{error}</p> : null}

          <button type="submit" className="cyber-button primary auth-submit" disabled={pending}>
            {pending ? "VERIFYING..." : "ACCESS SYSTEM"}
            <ArrowRight size={15} />
          </button>
        </form>

        <div className="auth-meta">
          <ShieldCheck size={16} />
          <span>Demo: admin@verity.local / verity123</span>
        </div>

        <Link href="/" className="auth-back-link">
          Return to overview
        </Link>
      </div>
    </div>
  );
}
