"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Suspense, useState } from "react";
import { LogOut, Menu, ScanSearch, ShieldCheck, X } from "lucide-react";

import { useAuth } from "@/components/auth-provider";

const NAV_LINKS = [
  { href: "/dashboard", label: "DASHBOARD" },
  { href: "/scan", label: "SCAN" },
  { href: "/history", label: "HISTORY" },
  { href: "/intelligence", label: "THREAT INTEL" },
  { href: "/community", label: "COMMUNITY" },
];

function NavbarInner() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const { isAuthenticated, logout } = useAuth();

  return (
    <header className="cyber-navbar">
      <div className="cyber-nav-inner">
        <Link href="/" className="cyber-brand" onClick={() => setOpen(false)}>
          <span className="brand-mark">✦</span>
          <span>WEBVERITY</span>
        </Link>

        <nav className="cyber-nav hidden md:flex">
          {NAV_LINKS.map((link) => {
            const active = pathname === link.href || pathname.startsWith(`${link.href}/`);
            return (
              <Link
                key={link.href}
                href={link.href}
                className={active ? "cyber-nav-link active" : "cyber-nav-link"}
              >
                {link.label}
              </Link>
            );
          })}

          {isAuthenticated ? (
            <>
              <span className="login-user">DEMO SESSION</span>
              <button type="button" className="cyber-nav-cta danger" onClick={logout}>
                <LogOut className="h-4 w-4" />
                <span>LOG OUT</span>
              </button>
            </>
          ) : (
            <Link href="/login" className="cyber-nav-cta">
              <ShieldCheck className="h-4 w-4" />
              <span>LOGIN</span>
            </Link>
          )}

          <Link href="/scan" className="cyber-nav-cta primary-cta">
            <span>START A PROJECT</span>
            <ScanSearch className="h-4 w-4" />
          </Link>
        </nav>

        <button
          className="cyber-menu-btn md:hidden"
          onClick={() => setOpen((v) => !v)}
          aria-label="Toggle navigation"
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {open && (
        <nav className="cyber-mobile-nav md:hidden">
          {NAV_LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              onClick={() => setOpen(false)}
              className={pathname === link.href ? "cyber-nav-link active" : "cyber-nav-link"}
            >
              {link.label}
            </Link>
          ))}

          {isAuthenticated ? (
            <button type="button" className="cyber-nav-cta danger" onClick={logout}>
              <LogOut className="h-4 w-4" />
              <span>LOG OUT</span>
            </button>
          ) : (
            <Link href="/login" onClick={() => setOpen(false)} className="cyber-nav-cta">
              <ShieldCheck className="h-4 w-4" />
              <span>LOGIN</span>
            </Link>
          )}

          <Link href="/scan" onClick={() => setOpen(false)} className="cyber-nav-cta primary-cta">
            <span>START A PROJECT</span>
            <ScanSearch className="h-4 w-4" />
          </Link>
        </nav>
      )}
    </header>
  );
}

export function Navbar() {
  return (
    <Suspense fallback={<div className="cyber-navbar h-16" />}>
      <NavbarInner />
    </Suspense>
  );
}
