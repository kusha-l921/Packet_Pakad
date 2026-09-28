'use client';

import React from 'react';
import { ShieldAlert, AlertOctagon, ArrowUpRight, Flame } from 'lucide-react';

export default function ThreatMatrixPage() {
  const threats = [
    {
      tactic: 'Initial Access (TA0001)',
      technique: 'T1133 - External Remote Services',
      description: 'Publicly reachable IKE listener on UDP 500 without aggressive mode disabling.',
      severity: 'LOW',
      mitigation: 'Enforce Main Mode / IKEv2 only; restrict peer IP range.',
    },
    {
      tactic: 'Command and Control (TA0011)',
      technique: 'T1573.002 - Asymmetric Encrypted Channel',
      description: 'Adversary leveraging legitimate IPsec tunnel for covert high-bandwidth data exfiltration.',
      severity: 'HIGH',
      mitigation: 'Implement packet size entropy monitoring and TFC validation.',
    },
    {
      tactic: 'Credential Access (TA0006)',
      technique: 'T1110 - Brute Force / Pre-Shared Key Attack',
      description: 'Weak PSK authentication in legacy IKEv1 negotiations susceptible to offline dictionary crack.',
      severity: 'CRITICAL',
      mitigation: 'Mandate digital signature auth (RSA-PSS or ECDSA) or strong 256-bit PSK.',
    },
  ];

  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-sentinel-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <ShieldAlert className="w-4 h-4 text-sentinel-critical" />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-sentinel-text uppercase">
              MITRE ATT&CK THREAT MATRIX CORRELATION
            </h1>
          </div>
          <p className="text-xs text-sentinel-text-muted">
            Mapping observable cryptographic vulnerabilities and anomalous encrypted flows to adversarial TTPs.
          </p>
        </div>

        <span className="text-xs text-sentinel-warning font-bold px-2.5 py-1 rounded border border-sentinel-warning/30 bg-sentinel-warning/10">
          3 THREAT VECTORS MAPPED
        </span>
      </div>

      <div className="space-y-4">
        {threats.map((item, i) => (
          <div key={i} className="p-5 rounded-xl border border-sentinel-border bg-[#101214] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                  item.severity === 'CRITICAL' ? 'bg-sentinel-critical/20 text-sentinel-critical border border-sentinel-critical/40' :
                  item.severity === 'HIGH' ? 'bg-sentinel-warning/20 text-sentinel-warning border border-sentinel-warning/40' :
                  'bg-sentinel-info/20 text-sentinel-info border border-sentinel-info/40'
                }`}>
                  {item.severity}
                </span>
                <span className="font-bold text-sm text-sentinel-text">{item.technique}</span>
              </div>
              <span className="text-[10px] text-sentinel-copper">{item.tactic}</span>
            </div>

            <p className="text-xs text-sentinel-text-muted leading-relaxed font-sans">
              {item.description}
            </p>

            <div className="p-3 rounded border border-sentinel-border bg-[#0B0C0D] text-[11px] text-sentinel-text-muted flex items-center justify-between">
              <div>Mitigation: <strong className="text-sentinel-mint">{item.mitigation}</strong></div>
              <span className="text-sentinel-copper cursor-pointer hover:underline flex items-center gap-1">
                <span>View ATT&CK Ref</span>
                <ArrowUpRight className="w-3 h-3" />
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
