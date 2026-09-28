'use client';

import React from 'react';
import Link from 'next/link';
import { Shield } from 'lucide-react';

export default function LandingFooter() {
  return (
    <footer className="py-12 border-t border-sentinel-border bg-[#0B0C0D] text-sentinel-text-muted font-mono text-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-10">
          {/* Brand */}
          <div className="md:col-span-1">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-6 h-6 rounded border border-sentinel-copper bg-sentinel-panel flex items-center justify-center text-sentinel-copper">
                <Shield className="w-3.5 h-3.5" />
              </div>
              <span className="font-bold text-sm tracking-wider text-sentinel-text">
                IPSEC SENTINEL
              </span>
              <span className="text-[9px] px-1 rounded border border-sentinel-copper/50 text-sentinel-copper">
                NTRO
              </span>
            </div>
            <p className="text-[11px] leading-relaxed text-sentinel-text-muted mb-4 font-sans">
              Intelligent IPsec automated security analysis, risk assessment, traffic intelligence, 
              and evidence-grounded reporting platform.
            </p>
            <div className="text-[10px] text-sentinel-copper">
              Clearance: SECRET // REL NTRO
            </div>
          </div>

          {/* Standards & RFCs */}
          <div>
            <div className="text-[11px] uppercase tracking-wider text-sentinel-text font-bold mb-3">
              STANDARDS
            </div>
            <ul className="space-y-1.5 text-[11px]">
              <li>RFC 7296 (IKEv2 Protocol)</li>
              <li>RFC 4301 (IPsec Architecture)</li>
              <li>RFC 4303 (ESP Encapsulation)</li>
              <li>RFC 8221 (ESP Cryptography)</li>
              <li>CNSA 2.0 Quantum Hardening</li>
            </ul>
          </div>

          {/* Console Modules */}
          <div>
            <div className="text-[11px] uppercase tracking-wider text-sentinel-text font-bold mb-3">
              CONSOLE MODULES
            </div>
            <ul className="space-y-1.5 text-[11px]">
              <li><Link href="/dashboard" className="hover:text-sentinel-copper transition-colors">Overview Dashboard</Link></li>
              <li><Link href="/dashboard/sessions" className="hover:text-sentinel-copper transition-colors">Session Dissection</Link></li>
              <li><Link href="/dashboard/rfc-compliance" className="hover:text-sentinel-copper transition-colors">RFC Compliance Engine</Link></li>
              <li><Link href="/dashboard/cryptographic-posture" className="hover:text-sentinel-copper transition-colors">Cryptographic Posture</Link></li>
              <li><Link href="/dashboard/traffic-intelligence" className="hover:text-sentinel-copper transition-colors">Traffic Intelligence</Link></li>
            </ul>
          </div>

          {/* Sovereign Defense */}
          <div>
            <div className="text-[11px] uppercase tracking-wider text-sentinel-text font-bold mb-3">
              FRAMEWORK
            </div>
            <div className="p-3 rounded border border-sentinel-border bg-[#101214] text-[10px] leading-relaxed">
              <div className="text-sentinel-mint font-semibold mb-1">
                ● NTRO PROBLEM 26160
              </div>
              <div>Sovereign Defense Cryptographic Assessment Benchmark</div>
              <div className="mt-2 text-sentinel-copper">
                Engine: SovereignNet v4.19
              </div>
            </div>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="pt-6 border-t border-sentinel-border/50 flex flex-col sm:flex-row items-center justify-between gap-4 text-[10px]">
          <div>
            © 2026 IPsec Sentinel. All rights reserved. Sovereign defense grade intelligence.
          </div>
          <div className="flex items-center gap-4 text-sentinel-text-muted">
            <span>Deterministic Scoring</span>
            <span>•</span>
            <span>Zero Payload Inspection</span>
            <span>•</span>
            <span className="text-sentinel-mint font-semibold">Ready for Operations</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
