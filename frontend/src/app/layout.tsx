
import type { Metadata } from "next";
import { Suspense, type ReactNode } from "react";

import { AuthGate } from "@/components/auth-gate";
import { AuthProvider } from "@/components/auth-provider";
import { Footer } from "@/components/footer";
import { Navbar } from "@/components/navbar";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "WebVerity — Phishing Detection & Website Trust Assessment",
    template: "%s | WebVerity",
  },
  description:
    "Multi-layered phishing detection and website trust assessment: URL analysis, DNS, TLS, HTTP security, threat intelligence, and explainable risk scoring.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="h-full antialiased" data-scroll-behavior="smooth">
      <body className="flex min-h-full flex-col">
        <AuthProvider>
          <Navbar />
          <main className="flex-1">
            <Suspense fallback={<div className="auth-loading">LOADING SESSION...</div>}>
              <AuthGate>{children}</AuthGate>
            </Suspense>
          </main>
          <Footer />
        </AuthProvider>
      </body>
    </html>
  );
}
