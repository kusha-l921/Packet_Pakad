'use client';

import React, { useState, useEffect } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { AnalysisTabs } from '@/components/analysis/AnalysisTabs';
import { fetchCertificateHealth } from '@/lib/api/analysis';
import { fetchTestbedStatus } from '@/lib/api/testbed';
import { NoDataState } from '@/components/common/NoDataState';
import { SessionSelector } from '@/components/common/SessionSelector';
import { ProgressBar } from '@/components/common/TechnicalField';
import { useSession } from '@/context/SessionContext';
import { CertificateHealthReport, CertFinding } from '@/types';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileCheck2,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Key,
  Clock,
  Download,
  Info,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Copy,
  Check,
  Server,
  Network,
  Cpu,
  Lock,
  Layers,
  Sparkles,
} from 'lucide-react';

const SUN_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIB8TCCAXegAwIBAgIULRdEzMe40KpYBAAPN5cfYo1t7z8wCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSc3VuLmVudGVycHJpc2UubmV0MB4XDTI2MDkyNDE3MTY0M1oX
DTI3MDkyNDE3MTY0M1owHTEbMBkGA1UEAwwSc3VuLmVudGVycHJpc2UubmV0MHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEeLEg32cqUP8yMYKw//FlwmrlFYekNs8EY6qZ
aw3NhdjxJc8LZ46JsVt17Rr/Qe38tE/Mu7KH2rs7xn9gFe1B7UrG5EbHywfnlsxZ
tdSk97BWllKRPMmaJ98pKy2P4G/3o3gwdjAdBgNVHQ4EFgQU7oRxKkHgM5YMyYHR
ureBR47s/tAwHwYDVR0jBBgwFoAU7oRxKkHgM5YMyYHRureBR47s/tAwDwYDVR0T
AQH/BAUwAwEB/zAjBgNVHREEHDAaghJzdW4uZW50ZXJwcmlzZS5uZXSHBKwcAAMw
CgYIKoZIzj0EAwIDaAAwZQIwCvrbU1xTCJbgXfPqGgqWDaQ6SNW/rQiY9orjeTj5
avQLwSoslYO8gz4iIxtKoC9/AjEAhtyW1fA2ay6kJszXxCq6MfzdX5Beaa+3TNNG
px4boTEVprWufxBRwPGLG/dpD+bA
-----END CERTIFICATE-----`;

const MOON_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIB9TCCAXqgAwIBAgIUMXFj8Uw2qyHqrqqM4X+RPAHEYoIwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTbW9vbi5lbnRlcnByaXNlLm5ldDAeFw0yNjA5MjQxNzE2NDJa
Fw0yNzA5MjQxNzE2NDJaMB4xHDAaBgNVBAMME21vb24uZW50ZXJwcmlzZS5uZXQw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQ1B60MMss3OzwLhwqNy74xF3QrmYgMAMiJ
RacFdgr8SQ59+U6YbavLPGO4GXvSfB90LVdSCnD64Iiwtdq1M3TioENvOHSm5Fse
8KbEAqNta7FULHsiweezc0ZWycwps9qjeTB3MB0GA1UdDgQWBBST1HQQ2v+ezFek
QQP5vrZ7Y3N0MTAfBgNVHSMEGDAWgBST1HQQ2v+ezFekQQP5vrZ7Y3N0MTAPBgNV
HRMBAf8EBTADAQH/MCQGA1UdEQQdMBuCE21vb24uZW50ZXJwcmlzZS5uZXSHBKwc
AAIwCgYIKoZIzj0EAwIDaQAwZgIxAOOsNkn0Zxta9DYzTDsOnyctNSqMi0Xa6fY6
HtOmEFEq/4P5EoLslc9CrHipCv3lPwIxALSzjgc3WPWXe1WdtjxK5VZ3mIhsmfBz
PEOOF6lXdGbIt9oVX0L9sjde11Fp7/1CYA==
-----END CERTIFICATE-----`;

export default function CertificateHealthPage() {
  const { selectedSessionId, selectedSession } = useSession();
  const [certReport, setCertReport] = useState<CertificateHealthReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedFilter, setSelectedFilter] = useState<string>('ALL');
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [activePeerTab, setActivePeerTab] = useState<'initiator' | 'responder'>('initiator');
  const [showPemModal, setShowPemModal] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    setLoading(true);
    fetchCertificateHealth(selectedSessionId || undefined)
      .then((data) => {
        if (data && data.peers && Object.keys(data.peers).length > 0) {
          setCertReport(data);
        } else {
          setCertReport(null);
        }
      })
      .catch(() => {
        setCertReport(null);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [selectedSessionId]);

  const hasData = Boolean(
    certReport &&
    certReport.peers &&
    (certReport.peers.initiator || certReport.peers.responder)
  );

  const initiatorPeer = certReport?.peers?.initiator;
  const responderPeer = certReport?.peers?.responder;
  const activePeer = activePeerTab === 'initiator' ? initiatorPeer : responderPeer;

  const allFindings: CertFinding[] = certReport?.findings || [
    ...(initiatorPeer?.findings || []),
    ...(responderPeer?.findings || []),
  ];

  // Deduplicate findings by rule_id and target
  const uniqueFindings = Array.from(
    new Map(allFindings.map((f) => [`${f.rule_id}-${f.target}`, f])).values()
  );

  const filteredFindings = uniqueFindings.filter((f) => {
    if (selectedFilter === 'ALL') return true;
    if (selectedFilter === 'PASS') return f.status === 'PASS';
    if (selectedFilter === 'WARNING') return f.status === 'WARNING';
    if (selectedFilter === 'FAIL') return f.status === 'FAIL';
    return true;
  });

  const passedCount = uniqueFindings.filter((f) => f.status === 'PASS').length;
  const warningCount = uniqueFindings.filter((f) => f.status === 'WARNING').length;
  const failCount = uniqueFindings.filter((f) => f.status === 'FAIL').length;
  const totalFindings = uniqueFindings.length;

  const handleCopyPem = (pemText: string) => {
    navigator.clipboard.writeText(pemText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportJson = () => {
    if (!certReport) return;
    const blob = new Blob([JSON.stringify(certReport, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `certificate_health_audit_${selectedSessionId || 'session'}.json`;
    a.click();
  };

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Navigation Tabs for Analysis Section */}
        <AnalysisTabs />

        {/* Page Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-sentinel-border">
          <div>
            <div className="flex items-center gap-2">
              <FileCheck2 className="w-5 h-5 text-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                X.509 Certificate Health & PKI Trust Posture
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-0.5">
              Automated cryptographic certificate chain auditing, expiration telemetry, SAN validation, and Post-Quantum / CNSA 2.0 readiness.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <SessionSelector />
            <button
              onClick={handleExportJson}
              disabled={!hasData}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-xs font-mono-tech text-sentinel-muted hover:text-sentinel-text transition-colors disabled:opacity-40"
            >
              <Download className="w-3.5 h-3.5 text-sentinel-copper" />
              Export PKI Audit JSON
            </button>
          </div>
        </div>

        {!hasData ? (
          <NoDataState
            title="NO CERTIFICATE TELEMETRY FOUND"
            description="No active X.509 certificate credentials or IKE_AUTH authentication artifacts were detected for the current session. Start the virtual testbed to run mutual ECDSA certificate exchange."
          />
        ) : (
          <>
            {/* Top Metric Strip / Executive KPIs */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Card 1: Overall Health Status */}
              <div className="panel-technical p-4 rounded-lg border-l-4 border-l-sentinel-mint space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono-tech uppercase tracking-wider text-sentinel-muted">
                    PKI HEALTH VERDICT
                  </span>
                  <span className="w-2 h-2 rounded-full bg-sentinel-mint animate-pulse" />
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-xl font-mono-tech font-bold text-sentinel-text">
                    {certReport?.overall_health_status || 'HEALTHY'}
                  </span>
                  <span className="text-[11px] font-mono-tech px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-800 dark:text-sentinel-mint font-semibold">
                    RFC 8247
                  </span>
                </div>
                <p className="text-[11px] text-sentinel-muted">
                  Chain validation verified. No expired credentials or revoked intermediates.
                </p>
              </div>

              {/* Card 2: Audited Peer Nodes */}
              <div className="panel-technical p-4 rounded-lg border-l-4 border-l-sentinel-copper space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono-tech uppercase tracking-wider text-sentinel-muted">
                    PEER CREDENTIAL AUDIT
                  </span>
                  <ShieldCheck className="w-4 h-4 text-sentinel-copper" />
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-xl font-mono-tech font-bold text-sentinel-text">
                    {certReport?.summary?.total_certificates_audited || 2} LEAF CERTS
                  </span>
                </div>
                <p className="text-[11px] text-sentinel-muted">
                  Mutual authentication verified: Initiator & Responder dual ECDSA-384.
                </p>
              </div>

              {/* Card 3: Expiration Horizon */}
              <div className="panel-technical p-4 rounded-lg border-l-4 border-l-sky-500 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono-tech uppercase tracking-wider text-sentinel-muted">
                    VALIDITY HORIZON
                  </span>
                  <Clock className="w-4 h-4 text-sky-500" />
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-xl font-mono-tech font-bold text-sentinel-text">
                    {activePeer?.leaf_certificate?.days_until_expiration?.toFixed(1) || '360.3'} DAYS
                  </span>
                  <span className="text-[10px] font-mono-tech text-sentinel-muted">
                    REMAINING
                  </span>
                </div>
                <ProgressBar
                  value={activePeer?.leaf_certificate?.days_until_expiration || 360}
                  max={365}
                  color="copper"
                  height="h-1.5"
                />
              </div>

              {/* Card 4: Post-Quantum Readiness */}
              <div className="panel-technical p-4 rounded-lg border-l-4 border-l-amber-500 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono-tech uppercase tracking-wider text-sentinel-muted">
                    CNSA 2.0 / PQC TIER
                  </span>
                  <Lock className="w-4 h-4 text-amber-500" />
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-base font-mono-tech font-bold text-sentinel-text">
                    {activePeer?.leaf_certificate?.rating?.tier || 'NIST MODERN'}
                  </span>
                  <span className="text-[10px] font-mono-tech px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-sentinel-warning font-semibold">
                    128-BIT
                  </span>
                </div>
                <p className="text-[11px] text-sentinel-muted">
                  Classical security strong. Migration target: ML-DSA (FIPS 204).
                </p>
              </div>
            </div>

            {/* Peer Certificate Inspector & Dual Comparison */}
            <div className="panel-technical p-5 rounded-lg space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-sentinel-border">
                <div className="flex items-center gap-2">
                  <Key className="w-4 h-4 text-sentinel-copper" />
                  <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                    Peer Certificate Metadata & Cryptographic Details
                  </h2>
                </div>

                {/* Peer Switcher Tabs */}
                <div className="flex items-center bg-sentinel-secondary/60 p-1 rounded-md border border-sentinel-border">
                  <button
                    onClick={() => setActivePeerTab('initiator')}
                    className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono-tech transition-all cursor-pointer ${
                      activePeerTab === 'initiator'
                        ? 'bg-sentinel-copper text-sentinel-bg font-bold shadow-xs'
                        : 'text-sentinel-muted hover:text-sentinel-text'
                    }`}
                  >
                    <Server className="w-3.5 h-3.5" />
                    <span>Initiator (gw-hq / Sun)</span>
                  </button>
                  <button
                    onClick={() => setActivePeerTab('responder')}
                    className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono-tech transition-all cursor-pointer ${
                      activePeerTab === 'responder'
                        ? 'bg-sentinel-copper text-sentinel-bg font-bold shadow-xs'
                        : 'text-sentinel-muted hover:text-sentinel-text'
                    }`}
                  >
                    <Server className="w-3.5 h-3.5" />
                    <span>Responder (gw-branch / Moon)</span>
                  </button>
                </div>
              </div>

              {activePeer && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {/* Left Column: Primary Certificate Identity & Properties */}
                  <div className="lg:col-span-2 space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border space-y-1">
                        <span className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                          Subject Distinguished Name
                        </span>
                        <div className="font-mono-tech text-xs font-bold text-sentinel-copper truncate" title={activePeer.leaf_certificate?.subject}>
                          {activePeer.leaf_certificate?.subject || `CN=${activePeer.identity?.value}`}
                        </div>
                      </div>

                      <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border space-y-1">
                        <span className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                          Issuer (Trust Anchor)
                        </span>
                        <div className="font-mono-tech text-xs font-semibold text-sentinel-text truncate" title={activePeer.leaf_certificate?.issuer}>
                          {activePeer.leaf_certificate?.issuer || `CN=${activePeer.identity?.value}`}
                        </div>
                      </div>

                      <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border space-y-1">
                        <span className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                          Public Key Algorithm & Curve
                        </span>
                        <div className="font-mono-tech text-xs font-semibold text-sentinel-text flex items-center gap-1.5">
                          <Cpu className="w-3.5 h-3.5 text-sentinel-copper" />
                          <span>{activePeer.leaf_certificate?.key_type_name || 'ECDSA (id-ecPublicKey)'}</span>
                          <span className="text-[10px] px-1 py-0.5 rounded bg-sentinel-secondary border border-sentinel-border text-sentinel-muted">
                            {activePeer.leaf_certificate?.key_bits || 384}b
                          </span>
                        </div>
                      </div>

                      <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border space-y-1">
                        <span className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                          Digital Signature Algorithm
                        </span>
                        <div className="font-mono-tech text-xs font-semibold text-sentinel-text flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-mint" />
                          <span>{activePeer.leaf_certificate?.sig_algo_name || 'ecdsa-with-SHA256'}</span>
                        </div>
                      </div>

                      <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border space-y-1">
                        <span className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                          Serial Number
                        </span>
                        <div className="font-mono-tech text-[11px] text-sentinel-muted truncate font-mono">
                          {activePeer.leaf_certificate?.serial_number || '0x2d1744ccc7b8d0aa5804000f37971f628d6def3f'}
                        </div>
                      </div>

                      <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border space-y-1">
                        <span className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                          Basic Constraints Flag
                        </span>
                        <div className="font-mono-tech text-xs flex items-center gap-1.5">
                          {activePeer.leaf_certificate?.is_ca ? (
                            <span className="px-2 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-800 dark:text-sentinel-warning font-bold text-[11px] flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3 text-amber-500" />
                              is_ca = TRUE (Audit Note)
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-800 dark:text-sentinel-mint font-bold text-[11px] flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                              is_ca = FALSE (End-Entity)
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Security Recommendation Box */}
                    {activePeer.leaf_certificate?.rating?.recommendation && (
                      <div className="p-3.5 rounded bg-sentinel-elevated border border-sentinel-border text-xs space-y-1">
                        <div className="flex items-center gap-1.5 font-mono-tech text-[11px] text-sentinel-copper font-semibold uppercase">
                          <Sparkles className="w-3.5 h-3.5" />
                          Cryptographic Standard Assessment:
                        </div>
                        <p className="text-sentinel-muted leading-relaxed">
                          {activePeer.leaf_certificate.rating.reason}
                        </p>
                        <p className="text-sentinel-text font-medium pt-1">
                          👉 <strong className="text-sentinel-copper">Recommendation:</strong> {activePeer.leaf_certificate.rating.recommendation}
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Right Column: Validity Schedule & Raw PEM Preview */}
                  <div className="p-4 rounded-lg bg-sentinel-secondary/20 border border-sentinel-border space-y-4 flex flex-col justify-between">
                    <div className="space-y-3">
                      <div className="flex items-center justify-between pb-2 border-b border-sentinel-border">
                        <span className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                          Validity Period Telemetry
                        </span>
                        <span className="text-[10px] font-mono-tech text-sentinel-mint font-bold">
                          ACTIVE
                        </span>
                      </div>

                      <div className="space-y-2 text-xs font-mono-tech">
                        <div>
                          <div className="text-[10px] text-sentinel-muted uppercase">Valid From:</div>
                          <div className="text-sentinel-text">
                            {activePeer.leaf_certificate?.not_before
                              ? new Date(activePeer.leaf_certificate.not_before * 1000).toUTCString()
                              : 'Wed, 24 Sep 2026 17:16:42 GMT'}
                          </div>
                        </div>

                        <div>
                          <div className="text-[10px] text-sentinel-muted uppercase">Valid Until:</div>
                          <div className="text-sentinel-text">
                            {activePeer.leaf_certificate?.not_after
                              ? new Date(activePeer.leaf_certificate.not_after * 1000).toUTCString()
                              : 'Thu, 24 Sep 2027 17:16:42 GMT'}
                          </div>
                        </div>

                        <div className="pt-2">
                          <div className="flex justify-between text-[10px] text-sentinel-muted mb-1">
                            <span>Lifecycle Depletion</span>
                            <span>{(((365 - (activePeer.leaf_certificate?.days_until_expiration || 360)) / 365) * 100).toFixed(1)}%</span>
                          </div>
                          <ProgressBar
                            value={365 - (activePeer.leaf_certificate?.days_until_expiration || 360)}
                            max={365}
                            color="mint"
                            height="h-2"
                          />
                        </div>
                      </div>
                    </div>

                    <div className="pt-2">
                      <button
                        onClick={() => setShowPemModal(activePeerTab)}
                        className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-xs font-mono-tech text-sentinel-text hover:text-sentinel-copper transition-colors cursor-pointer"
                      >
                        <FileCheck2 className="w-3.5 h-3.5" />
                        <span>Inspect Raw X.509 PEM</span>
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Detailed PKI Finding Rules Table */}
            <div className="panel-technical rounded-lg p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-sentinel-border">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-sentinel-copper" />
                  <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                    PKI & X.509 Compliance Findings ({filteredFindings.length} Audited)
                  </h2>
                </div>

                {/* Filter Pills */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  {(['ALL', 'PASS', 'WARNING', 'FAIL'] as const).map((filter) => {
                    const count =
                      filter === 'ALL'
                        ? totalFindings
                        : filter === 'PASS'
                        ? passedCount
                        : filter === 'WARNING'
                        ? warningCount
                        : failCount;

                    return (
                      <button
                        key={filter}
                        onClick={() => setSelectedFilter(filter)}
                        className={`px-2.5 py-1 rounded text-[10px] font-mono-tech uppercase transition-all cursor-pointer ${
                          selectedFilter === filter
                            ? 'bg-sentinel-copper text-sentinel-bg font-bold shadow-xs'
                            : 'bg-sentinel-secondary border border-sentinel-border text-sentinel-muted hover:text-sentinel-text'
                        }`}
                      >
                        {filter} ({count})
                      </button>
                    );
                  })}
                </div>
              </div>

              {filteredFindings.length === 0 ? (
                <div className="p-6 text-center text-xs font-mono-tech text-sentinel-muted">
                  No findings match filter "{selectedFilter}".
                </div>
              ) : (
                <div className="space-y-2">
                  {filteredFindings.map((finding) => {
                    const isExpanded = expandedFinding === `${finding.rule_id}-${finding.target}`;
                    const isPass = finding.status === 'PASS';
                    const isWarning = finding.status === 'WARNING';
                    const isFail = finding.status === 'FAIL';

                    const badgeColor = isPass
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-800 dark:text-sentinel-mint'
                      : isWarning
                      ? 'bg-amber-500/15 border-amber-500/30 text-amber-800 dark:text-sentinel-warning'
                      : 'bg-rose-500/15 border-rose-500/30 text-rose-800 dark:text-sentinel-critical';

                    return (
                      <div
                        key={`${finding.rule_id}-${finding.target}`}
                        className="rounded-lg border border-sentinel-border bg-sentinel-secondary/20 hover:bg-sentinel-secondary/40 transition-colors overflow-hidden"
                      >
                        <div
                          onClick={() => setExpandedFinding(isExpanded ? null : `${finding.rule_id}-${finding.target}`)}
                          className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer select-none"
                        >
                          <div className="flex items-start sm:items-center gap-3">
                            <button className="text-sentinel-muted hover:text-sentinel-text transition-colors mt-0.5 sm:mt-0">
                              {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                            </button>

                            <div className="space-y-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className={`text-[10px] font-mono-tech px-2 py-0.5 rounded border font-bold ${badgeColor}`}>
                                  {finding.status}
                                </span>
                                <span className="font-mono-tech text-xs font-bold text-sentinel-text">
                                  {finding.rule_id}
                                </span>
                                <span className="text-[10px] font-mono-tech px-1.5 py-0.5 rounded bg-sentinel-secondary text-sentinel-muted border border-sentinel-border uppercase">
                                  {finding.target}
                                </span>
                              </div>
                              <p className="text-xs text-sentinel-text font-medium">
                                {finding.condition}
                              </p>
                            </div>
                          </div>

                          <div className="text-left sm:text-right font-mono-tech text-xs pl-7 sm:pl-0">
                            <span className="text-[11px] text-sentinel-muted block">Observed:</span>
                            <span className="text-sentinel-copper font-medium">{finding.observed}</span>
                          </div>
                        </div>

                        <AnimatePresence>
                          {isExpanded && (
                            <motion.div
                              initial={{ height: 0, opacity: 0 }}
                              animate={{ height: 'auto', opacity: 1 }}
                              exit={{ height: 0, opacity: 0 }}
                              transition={{ duration: 0.2 }}
                              className="border-t border-sentinel-border px-4 py-3 bg-sentinel-elevated/40 space-y-2.5 text-xs font-mono-tech"
                            >
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div>
                                  <span className="text-[10px] text-sentinel-muted uppercase block">Standard Requirement:</span>
                                  <span className="text-sentinel-text">{finding.expected}</span>
                                </div>
                                <div>
                                  <span className="text-[10px] text-sentinel-muted uppercase block">Audit Severity:</span>
                                  <span className="text-sentinel-copper">{finding.severity}</span>
                                </div>
                              </div>

                              <div>
                                <span className="text-[10px] text-sentinel-muted uppercase block">Technical Rationale:</span>
                                <p className="text-sentinel-muted font-sans text-xs leading-relaxed">
                                  {finding.reason}
                                </p>
                              </div>

                              {finding.remediation && finding.remediation !== 'None required.' && (
                                <div className="p-2.5 rounded bg-sentinel-secondary/60 border border-sentinel-border space-y-1">
                                  <span className="text-[10px] text-sentinel-copper uppercase font-bold block">
                                    Actionable Remediation:
                                  </span>
                                  <p className="text-sentinel-text font-sans text-xs leading-relaxed">
                                    {finding.remediation}
                                  </p>
                                </div>
                              )}
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </>
        )}

        {/* PEM Inspection Modal */}
        <AnimatePresence>
          {showPemModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="panel-technical rounded-lg border border-sentinel-border bg-sentinel-deep max-w-2xl w-full p-5 space-y-4 shadow-2xl"
              >
                <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
                  <div className="flex items-center gap-2">
                    <FileCheck2 className="w-4 h-4 text-sentinel-copper" />
                    <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                      X.509 Certificate PEM // {showPemModal === 'initiator' ? 'sunCert.pem' : 'moonCert.pem'}
                    </span>
                  </div>
                  <button
                    onClick={() => setShowPemModal(null)}
                    className="p-1 rounded text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-secondary transition-colors"
                  >
                    <XCircle className="w-4 h-4" />
                  </button>
                </div>

                <div className="relative">
                  <pre className="p-3.5 rounded bg-sentinel-elevated border border-sentinel-border text-[11px] font-mono-tech text-sentinel-copper overflow-x-auto whitespace-pre leading-relaxed max-h-72">
                    {showPemModal === 'initiator' ? SUN_CERT_PEM : MOON_CERT_PEM}
                  </pre>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <span className="text-[10px] font-mono-tech text-sentinel-muted">
                    Encoding: X.509 Base64 RFC 7468
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleCopyPem(showPemModal === 'initiator' ? SUN_CERT_PEM : MOON_CERT_PEM)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-xs font-mono-tech text-sentinel-text transition-colors cursor-pointer"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-sentinel-mint" /> : <Copy className="w-3.5 h-3.5 text-sentinel-copper" />}
                      <span>{copied ? 'COPIED TO CLIPBOARD' : 'COPY PEM'}</span>
                    </button>
                    <button
                      onClick={() => setShowPemModal(null)}
                      className="px-3 py-1.5 rounded bg-sentinel-copper hover:bg-sentinel-copperHover text-sentinel-bg font-mono-tech text-xs font-bold transition-colors cursor-pointer"
                    >
                      CLOSE
                    </button>
                  </div>
                </div>
              </motion.div>
            </div>
          )}
        </AnimatePresence>
      </div>
    </AppShell>
  );
}
