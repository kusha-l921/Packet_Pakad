'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { useRouter } from 'next/navigation';
import {
  Lock,
  ArrowRight,
  Shield,
  Layers,
  Activity,
  Maximize2,
  ExternalLink,
  Cpu,
  Key,
} from 'lucide-react';
import { Session } from '@/types';

interface TunnelVisualizationProps {
  session: Session;
}

export const TunnelVisualization: React.FC<TunnelVisualizationProps> = ({ session }) => {
  const router = useRouter();
  const [isHovered, setIsHovered] = useState(false);
  const [selectedPayloadType, setSelectedPayloadType] = useState<'ESP' | 'IKE'>('ESP');

  return (
    <div className="panel-technical p-5 rounded-lg space-y-4">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-sentinel-border">
        <div className="flex items-center gap-2">
          <Lock className="w-4 h-4 text-sentinel-copper" />
          <span className="font-mono-tech text-xs font-semibold text-sentinel-text uppercase tracking-wider">
            Live IPsec Tunnel Topography & Real-Time Dissection
          </span>
          <span className="text-[10px] font-mono-tech px-1.5 py-0.5 rounded bg-sentinel-mint/10 text-sentinel-mint border border-sentinel-mint/30">
            ESTABLISHED
          </span>
        </div>
        <div className="flex items-center gap-3 text-[11px] font-mono-tech text-sentinel-muted">
          <span>TX: 14.8 Mbps</span>
          <span className="text-sentinel-border">|</span>
          <span>RTT: 4.2ms</span>
          <span className="text-sentinel-border">|</span>
          <button
            onClick={() => router.push(`/sessions/${session.id}`)}
            className="flex items-center gap-1 text-sentinel-copper hover:underline"
          >
            Session Analysis <ExternalLink className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Main Network Topography Stage */}
      <div className="relative py-6 px-4 bg-sentinel-deep/70 border border-sentinel-border rounded-lg overflow-hidden">
        {/* Subtle background grid pattern */}
        <div
          className="absolute inset-0 opacity-25 pointer-events-none"
          style={{
            backgroundImage:
              'radial-gradient(circle, rgba(var(--color-border-rgb), 0.4) 1px, transparent 1px)',
            backgroundSize: '16px 16px',
          }}
        />

        <div className="relative flex flex-col lg:flex-row items-center justify-between gap-6 z-10">
          {/* CLIENT ENDPOINT (Initiator) */}
          <div className="w-full lg:w-56 p-3.5 bg-sentinel-elevated border border-sentinel-border rounded-md shadow-sm space-y-2">
            <div className="flex items-center justify-between text-[10px] font-mono-tech text-sentinel-muted">
              <span className="px-1 py-0.5 rounded bg-sentinel-secondary border border-sentinel-border">
                INITIATOR
              </span>
              <span className="flex items-center gap-1 text-sentinel-mint">
                <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint" />
                ONLINE
              </span>
            </div>
            <div>
              <div className="text-xs font-semibold text-sentinel-text font-sans">
                CLIENT (Security Domain A)
              </div>
              <div className="font-mono-tech text-xs text-sentinel-copper font-medium mt-0.5">
                {session.source}:500
              </div>
            </div>
            <div className="pt-2 border-t border-sentinel-border text-[10px] font-mono-tech text-sentinel-muted space-y-0.5">
              <div className="truncate">ID: fqdn:client.delhi.ntro.in</div>
              <div>NAT-T: ENABLED (PORT 4500 FLOW)</div>
            </div>
          </div>

          {/* THE IPSEC TUNNEL & MOVING PACKET ARTERY */}
          <div className="flex-1 w-full relative flex flex-col items-center justify-center">
            {/* Tunnel Frame / Outer Security Envelope */}
            <motion.div
              onClick={() => router.push(`/sessions/${session.id}`)}
              onHoverStart={() => setIsHovered(true)}
              onHoverEnd={() => setIsHovered(false)}
              className="w-full p-4 rounded-lg border-2 border-dashed border-sentinel-copper/50 bg-sentinel-secondary/40 hover:border-sentinel-copper hover:bg-sentinel-copper/5 transition-all cursor-pointer relative group"
            >
              {/* Corner brackets */}
              <div className="absolute top-1 left-1.5 text-[9px] font-mono-tech text-sentinel-copper/60">
                ╔
              </div>
              <div className="absolute top-1 right-1.5 text-[9px] font-mono-tech text-sentinel-copper/60">
                ╗
              </div>
              <div className="absolute bottom-1 left-1.5 text-[9px] font-mono-tech text-sentinel-copper/60">
                ╚
              </div>
              <div className="absolute bottom-1 right-1.5 text-[9px] font-mono-tech text-sentinel-copper/60">
                ╝
              </div>

              {/* Tunnel Header */}
              <div className="flex items-center justify-between text-xs font-mono-tech mb-3">
                <div className="flex items-center gap-2">
                  <Shield className="w-3.5 h-3.5 text-sentinel-copper" />
                  <span className="font-bold text-sentinel-text tracking-wide">
                    IPSEC SECURE TUNNEL ENVELOPE (RFC 4303)
                  </span>
                </div>
                <div className="text-[10px] text-sentinel-muted group-hover:text-sentinel-copper flex items-center gap-1 font-mono-tech">
                  <span>SPI_IN: {session.spiIn}</span>
                  <span className="text-sentinel-border">/</span>
                  <span>SPI_OUT: {session.spiOut}</span>
                </div>
              </div>

              {/* Packet Traffic Stream Track */}
              <div className="relative h-10 w-full bg-sentinel-deep/90 border border-sentinel-border rounded flex items-center overflow-hidden px-2 mb-3">
                {/* Horizontal flow line */}
                <div className="absolute inset-x-0 h-[1px] bg-sentinel-border" />

                {/* Animated Packet Tokens Moving Left-to-Right */}
                <motion.div
                  className="flex items-center gap-16 absolute"
                  animate={{
                    x: ['-20%', '100%'],
                  }}
                  transition={{
                    repeat: Infinity,
                    duration: 4.5,
                    ease: 'linear',
                  }}
                >
                  <div className="px-2 py-0.5 rounded bg-sentinel-mint/20 border border-sentinel-mint text-sentinel-mint font-mono-tech text-[10px] flex items-center gap-1 whitespace-nowrap shadow-sm">
                    <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint" />
                    ESP #18419
                  </div>
                  <div className="px-2 py-0.5 rounded bg-sentinel-copper/20 border border-sentinel-copper text-sentinel-copper font-mono-tech text-[10px] flex items-center gap-1 whitespace-nowrap shadow-sm">
                    <span className="w-1.5 h-1.5 rounded-full bg-sentinel-copper" />
                    IKEv2 #36
                  </div>
                  <div className="px-2 py-0.5 rounded bg-sentinel-mint/20 border border-sentinel-mint text-sentinel-mint font-mono-tech text-[10px] flex items-center gap-1 whitespace-nowrap shadow-sm">
                    <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint" />
                    ESP #18420
                  </div>
                  <div className="px-2 py-0.5 rounded bg-sentinel-mint/20 border border-sentinel-mint text-sentinel-mint font-mono-tech text-[10px] flex items-center gap-1 whitespace-nowrap shadow-sm">
                    <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint" />
                    ESP #18421
                  </div>
                </motion.div>
              </div>

              {/* Tunnel Crypto Badges */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
                <div className="p-1.5 rounded bg-sentinel-elevated border border-sentinel-border">
                  <div className="text-[9px] font-mono-tech text-sentinel-muted">ENCRYPTION</div>
                  <div className="text-xs font-mono-tech font-bold text-sentinel-text">
                    {session.encryption}
                  </div>
                </div>
                <div className="p-1.5 rounded bg-sentinel-elevated border border-sentinel-border">
                  <div className="text-[9px] font-mono-tech text-sentinel-muted">DIFFIE-HELLMAN</div>
                  <div className="text-xs font-mono-tech font-bold text-sentinel-copper">
                    DH GROUP 19
                  </div>
                </div>
                <div className="p-1.5 rounded bg-sentinel-elevated border border-sentinel-border">
                  <div className="text-[9px] font-mono-tech text-sentinel-muted">FORWARD SECRECY</div>
                  <div className="text-xs font-mono-tech font-bold text-sentinel-mint">
                    PFS ENABLED
                  </div>
                </div>
                <div className="p-1.5 rounded bg-sentinel-elevated border border-sentinel-border">
                  <div className="text-[9px] font-mono-tech text-sentinel-muted">PROTOCOL LAYER</div>
                  <div className="text-xs font-mono-tech font-bold text-sentinel-text">
                    ESP (UDP 4500)
                  </div>
                </div>
              </div>

              <div className="mt-2.5 text-center text-[11px] font-mono-tech text-sentinel-muted group-hover:text-sentinel-copper transition-colors">
                [ Click tunnel envelope to inspect session telemetry & cryptographic state ]
              </div>
            </motion.div>
          </div>

          {/* SERVER ENDPOINT (Responder) */}
          <div className="w-full lg:w-56 p-3.5 bg-sentinel-elevated border border-sentinel-border rounded-md shadow-sm space-y-2">
            <div className="flex items-center justify-between text-[10px] font-mono-tech text-sentinel-muted">
              <span className="px-1 py-0.5 rounded bg-sentinel-secondary border border-sentinel-border">
                RESPONDER
              </span>
              <span className="flex items-center gap-1 text-sentinel-mint">
                <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint" />
                SYNCHRONIZED
              </span>
            </div>
            <div>
              <div className="text-xs font-semibold text-sentinel-text font-sans">
                GATEWAY (HQ Core Border)
              </div>
              <div className="font-mono-tech text-xs text-sentinel-copper font-medium mt-0.5">
                {session.destination}:4500
              </div>
            </div>
            <div className="pt-2 border-t border-sentinel-border text-[10px] font-mono-tech text-sentinel-muted space-y-0.5">
              <div className="truncate">ID: ip:10.0.2.20</div>
              <div>strongSwan 5.9.11 (STRICT-OE)</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
