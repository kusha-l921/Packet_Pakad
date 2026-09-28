'use client';

import React from 'react';
import { Lock, Shield, Check, AlertTriangle, Key, Cpu, Award, Zap } from 'lucide-react';

export default function CryptographicPosturePage() {
  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-sentinel-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Lock className="w-4 h-4 text-sentinel-copper" />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-sentinel-text uppercase">
              CRYPTOGRAPHIC POSTURE & QUANTUM HARDENING
            </h1>
          </div>
          <p className="text-xs text-sentinel-text-muted">
            Suite-B / CNSA 2.0 evaluation, algorithm hygiene, ephemeral entropy, and post-quantum readiness.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-sentinel-mint font-bold px-2.5 py-1 rounded border border-sentinel-mint/30 bg-sentinel-mint/10">
            SUITE-B COMPLIANT (GRADE A-)
          </span>
        </div>
      </div>

      {/* Top 3 Pillar Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-5 rounded-xl border border-sentinel-border bg-[#101214] space-y-3">
          <div className="flex items-center justify-between text-sentinel-copper">
            <span className="font-bold text-xs uppercase">ENCRYPTION ALGORITHMS</span>
            <Lock className="w-4 h-4" />
          </div>
          <div className="text-2xl font-bold text-sentinel-text">AES-256-GCM</div>
          <div className="text-xs text-sentinel-text-muted">
            Authenticated Encryption with Associated Data (AEAD). 128-bit ICV integrity tag.
          </div>
          <div className="pt-2 border-t border-sentinel-border/50 text-[10px] text-sentinel-mint">
            ✓ 0 Sweet32 / Block Collision Vulnerabilities
          </div>
        </div>

        <div className="p-5 rounded-xl border border-sentinel-border bg-[#101214] space-y-3">
          <div className="flex items-center justify-between text-sentinel-copper">
            <span className="font-bold text-xs uppercase">KEY EXCHANGE & PFS</span>
            <Key className="w-4 h-4" />
          </div>
          <div className="text-2xl font-bold text-sentinel-text">DIFFIE-HELLMAN 19</div>
          <div className="text-xs text-sentinel-text-muted">
            256-bit Elliptic Curve (NIST P-256). Forward Secrecy enabled on parent SA.
          </div>
          <div className="pt-2 border-t border-sentinel-border/50 text-[10px] text-sentinel-warning">
            ⚠ Child SA rekey lacks ephemeral KE payload
          </div>
        </div>

        <div className="p-5 rounded-xl border border-sentinel-border bg-[#101214] space-y-3">
          <div className="flex items-center justify-between text-sentinel-copper">
            <span className="font-bold text-xs uppercase">QUANTUM RESISTANCE</span>
            <Cpu className="w-4 h-4" />
          </div>
          <div className="text-2xl font-bold text-sentinel-text">CNSA 2.0 TRANSITION</div>
          <div className="text-xs text-sentinel-text-muted">
            ML-KEM / Kyber-768 hybrid proposal validation ready for post-quantum IPsec.
          </div>
          <div className="pt-2 border-t border-sentinel-border/50 text-[10px] text-sentinel-info">
            ● Hybrid Post-Quantum Proposal Available
          </div>
        </div>
      </div>

      {/* Comprehensive Algorithm Matrix */}
      <div className="p-6 rounded-xl border border-sentinel-border bg-[#101214] space-y-4">
        <div className="text-xs font-bold text-sentinel-text uppercase tracking-wider">
          OBSERVED CRYPTOGRAPHIC PROPOSALS & TRANSFORM MATRIX
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-sentinel-border text-[10px] text-sentinel-text-muted uppercase">
                <th className="py-2.5 px-3">TRANSFORM TYPE</th>
                <th className="py-2.5 px-3">NEGOTIATED PRIMITIVE</th>
                <th className="py-2.5 px-3">KEY STRENGTH</th>
                <th className="py-2.5 px-3">RFC STATUS</th>
                <th className="py-2.5 px-3">HARDENING RECOMMENDATION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sentinel-border/50 text-xs">
              <tr className="hover:bg-[#151719]">
                <td className="py-2.5 px-3 font-bold text-sentinel-text">ENCR (Encryption)</td>
                <td className="py-2.5 px-3 text-sentinel-copper">AES_GCM_16_256</td>
                <td className="py-2.5 px-3 text-sentinel-text">256-bit AEAD</td>
                <td className="py-2.5 px-3 text-sentinel-mint">MUST (RFC 8221)</td>
                <td className="py-2.5 px-3 text-sentinel-text-muted">Compliant with Sovereign Defense</td>
              </tr>
              <tr className="hover:bg-[#151719]">
                <td className="py-2.5 px-3 font-bold text-sentinel-text">PRF (Pseudorandom)</td>
                <td className="py-2.5 px-3 text-sentinel-copper">PRF_HMAC_SHA2_384</td>
                <td className="py-2.5 px-3 text-sentinel-text">384-bit</td>
                <td className="py-2.5 px-3 text-sentinel-mint">MUST (RFC 8221)</td>
                <td className="py-2.5 px-3 text-sentinel-text-muted">Strong collision resistance</td>
              </tr>
              <tr className="hover:bg-[#151719]">
                <td className="py-2.5 px-3 font-bold text-sentinel-text">D-H (Key Exchange)</td>
                <td className="py-2.5 px-3 text-sentinel-copper">GROUP 19 (ECP-256)</td>
                <td className="py-2.5 px-3 text-sentinel-text">128-bit equiv</td>
                <td className="py-2.5 px-3 text-sentinel-mint">RECOMMENDED</td>
                <td className="py-2.5 px-3 text-sentinel-text-muted">Upgrade to Group 20 (ECP-384) for CNSA</td>
              </tr>
              <tr className="hover:bg-[#151719]">
                <td className="py-2.5 px-3 font-bold text-sentinel-text">INTEG (Integrity)</td>
                <td className="py-2.5 px-3 text-sentinel-copper">NONE (AEAD Implicit)</td>
                <td className="py-2.5 px-3 text-sentinel-text">128-bit Tag</td>
                <td className="py-2.5 px-3 text-sentinel-mint">CORRECT</td>
                <td className="py-2.5 px-3 text-sentinel-text-muted">Combined mode eliminates MAC-then-Encrypt</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
