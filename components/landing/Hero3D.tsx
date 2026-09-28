'use client';

import React, { useState, useRef, useEffect, useMemo, useCallback } from 'react';
import { useTheme } from '@/lib/theme/ThemeProvider';

interface Hero3DProps {
  onTransitionStart?: () => void;
  isTransitioning?: boolean;
}

// ThinkingOrb Constellation Node around Core
interface ConstellationNode {
  baseAngle: number;
  speed: number;
  radiusX: number;
  radiusY: number;
  tilt: number;
  size: number;
  colorType: 'copper' | 'mint' | 'bone';
}

// 3D Depth Layer for Packets
type DepthLayer = 'bg' | 'mid' | 'fg';

// Dynamic Telemetry Packet
interface TelemetryPacket {
  id: number;
  type: 'IKE' | 'ESP' | 'CTRL' | 'BURST' | 'RISK';
  depth: DepthLayer;
  pathId: 'ingress' | 'tunnelUpper' | 'tunnelCenter' | 'tunnelLower' | 'egressUpper' | 'egressLower' | 'reverse';
  progress: number;
  speed: number;
  size: number;
  trailLength: number;
  burstIndex?: number;
}

export default function Hero3D({ onTransitionStart, isTransitioning = false }: Hero3DProps) {
  const { theme } = useTheme();
  const isLight = theme === 'light';

  const containerRef = useRef<HTMLDivElement>(null);
  const orbCanvasRef = useRef<HTMLCanvasElement>(null);
  const animFrameRef = useRef<number | null>(null);

  // Smooth Parallax Lerp
  const targetMouseRef = useRef({ x: 0, y: 0 });
  const currentMouseRef = useRef({ x: 0, y: 0 });
  const [mouseParallax, setMouseParallax] = useState({ x: 0, y: 0 });

  // Interactive Hover State (tunnelEntrance, ike, core, traffic)
  const [hoveredMechanism, setHoveredMechanism] = useState<'tunnelEntrance' | 'ike' | 'core' | 'traffic' | null>(null);
  const [coreActivity, setCoreActivity] = useState<number>(1.0);
  const [burstCycle, setBurstCycle] = useState<number>(0);

  // Color tokens
  const colors = useMemo(() => {
    if (isLight) {
      return {
        bg: '#F3F2EE',
        grid: '#E2DED5',
        gridSubtle: 'rgba(215, 212, 204, 0.45)',
        graphite: '#242628',
        graphiteMuted: '#686A67',
        copper: '#B9653E',
        copperGlow: 'rgba(185, 101, 62, 0.22)',
        copperTrace: 'rgba(185, 101, 62, 0.35)',
        mint: '#5E8E7D',
        mintGlow: 'rgba(94, 142, 125, 0.22)',
        amber: '#B88828',
        bone: '#383B3E',
        tunnelFill: 'rgba(36, 38, 40, 0.02)',
        tunnelWall: 'rgba(36, 38, 40, 0.05)',
        tunnelStroke: 'rgba(36, 38, 40, 0.16)',
        coreBg: '#FFFFFF',
        coreBorder: '#242628',
      };
    }
    return {
      bg: '#0B0C0D',
      grid: '#1F2225',
      gridSubtle: 'rgba(255, 255, 255, 0.035)',
      graphite: '#9B9D9A',
      graphiteMuted: '#525559',
      copper: '#C47A52',
      copperGlow: 'rgba(196, 122, 82, 0.3)',
      copperTrace: 'rgba(196, 122, 82, 0.45)',
      mint: '#8FB8A8',
      mintGlow: 'rgba(143, 184, 168, 0.25)',
      amber: '#D7A84D',
      bone: '#E8E3D8',
      tunnelFill: 'rgba(196, 122, 82, 0.025)',
      tunnelWall: 'rgba(196, 122, 82, 0.06)',
      tunnelStroke: 'rgba(255, 255, 255, 0.14)',
      coreBg: '#121416',
      coreBorder: '#C47A52',
    };
  }, [isLight]);

  // Spatial Coordinate Dimensions: 1400 x 700 viewBox
  // Central IPsec Core is RIGHT-CENTERED at 63.6% width (CX = 890, CY = 350)
  // Continuous Tunnel Wall begins BEHIND the hero headline at X_START = 220
  // First Cross-Section Oval sits deeper inside the tunnel at X = 520 (NOT the tunnel mouth!)
  const CX = 890;
  const CY = 350;
  const X_START = 220;

  // 1. ThinkingOrb Constellation Nodes around REDUCED Core (32x32px)
  const constellationNodes = useRef<ConstellationNode[]>([
    { baseAngle: 0.1, speed: 0.7, radiusX: 26, radiusY: 22, tilt: 0.2, size: 1.7, colorType: 'copper' },
    { baseAngle: 0.8, speed: -0.6, radiusX: 35, radiusY: 29, tilt: -0.3, size: 1.6, colorType: 'mint' },
    { baseAngle: 1.5, speed: 0.8, radiusX: 30, radiusY: 24, tilt: 0.4, size: 1.5, colorType: 'bone' },
    { baseAngle: 2.2, speed: -0.5, radiusX: 42, radiusY: 34, tilt: -0.1, size: 1.8, colorType: 'copper' },
    { baseAngle: 2.9, speed: 0.9, radiusX: 24, radiusY: 20, tilt: 0.6, size: 1.4, colorType: 'mint' },
    { baseAngle: 3.6, speed: -0.7, radiusX: 38, radiusY: 31, tilt: -0.5, size: 1.6, colorType: 'copper' },
    { baseAngle: 4.3, speed: 0.6, radiusX: 32, radiusY: 26, tilt: 0.1, size: 1.5, colorType: 'bone' },
    { baseAngle: 5.0, speed: -0.8, radiusX: 46, radiusY: 37, tilt: 0.3, size: 1.8, colorType: 'mint' },
    { baseAngle: 5.7, speed: 0.5, radiusX: 28, radiusY: 23, tilt: -0.4, size: 1.5, colorType: 'copper' },
  ]).current;

  // 2. 28 Active Packets traversing through the Funnel
  const packetsRef = useRef<TelemetryPacket[]>([
    // FOREGROUND LAYER (Crisp, active, slight comet trail, larger near funnel mouth)
    { id: 1, type: 'ESP', depth: 'fg', pathId: 'tunnelCenter', progress: 0.18, speed: 0.0022, size: 5.0, trailLength: 20 },
    { id: 2, type: 'IKE', depth: 'fg', pathId: 'tunnelUpper', progress: 0.45, speed: 0.0018, size: 5.0, trailLength: 18 },
    { id: 3, type: 'ESP', depth: 'fg', pathId: 'tunnelLower', progress: 0.72, speed: 0.0024, size: 4.6, trailLength: 18 },
    { id: 4, type: 'CTRL', depth: 'fg', pathId: 'ingress', progress: 0.15, speed: 0.0026, size: 5.2, trailLength: 20 }, // Emerging at funnel mouth
    { id: 5, type: 'ESP', depth: 'fg', pathId: 'egressUpper', progress: 0.60, speed: 0.0023, size: 4.8, trailLength: 22 },
    { id: 6, type: 'RISK', depth: 'fg', pathId: 'egressLower', progress: 0.85, speed: 0.0021, size: 4.9, trailLength: 16 },
    { id: 7, type: 'ESP', depth: 'fg', pathId: 'reverse', progress: 0.40, speed: 0.0022, size: 4.5, trailLength: 18 },

    // MIDGROUND LAYER (Standard telemetry flow)
    { id: 8, type: 'IKE', depth: 'mid', pathId: 'ingress', progress: 0.06, speed: 0.0019, size: 4.2, trailLength: 16 },
    { id: 9, type: 'ESP', depth: 'mid', pathId: 'ingress', progress: 0.78, speed: 0.0021, size: 3.7, trailLength: 13 },
    { id: 10, type: 'ESP', depth: 'mid', pathId: 'tunnelUpper', progress: 0.08, speed: 0.0023, size: 4.0, trailLength: 16 },
    { id: 11, type: 'CTRL', depth: 'mid', pathId: 'tunnelCenter', progress: 0.32, speed: 0.0027, size: 3.5, trailLength: 12 },
    { id: 12, type: 'ESP', depth: 'mid', pathId: 'tunnelCenter', progress: 0.62, speed: 0.0022, size: 4.1, trailLength: 15 },
    { id: 13, type: 'IKE', depth: 'mid', pathId: 'tunnelLower', progress: 0.22, speed: 0.0017, size: 4.2, trailLength: 13 },
    { id: 14, type: 'ESP', depth: 'mid', pathId: 'tunnelLower', progress: 0.82, speed: 0.0024, size: 3.9, trailLength: 15 },
    { id: 15, type: 'CTRL', depth: 'mid', pathId: 'egressUpper', progress: 0.25, speed: 0.0025, size: 3.5, trailLength: 13 },
    { id: 16, type: 'ESP', depth: 'mid', pathId: 'egressLower', progress: 0.45, speed: 0.0021, size: 4.0, trailLength: 14 },
    { id: 17, type: 'ESP', depth: 'mid', pathId: 'reverse', progress: 0.75, speed: 0.0023, size: 3.9, trailLength: 15 },

    // BURST CLUSTER (Traveling in close succession through ESP corridor)
    { id: 18, type: 'BURST', depth: 'mid', pathId: 'tunnelCenter', progress: 0.86, speed: 0.0031, size: 3.7, trailLength: 14, burstIndex: 0 },
    { id: 19, type: 'BURST', depth: 'mid', pathId: 'tunnelCenter', progress: 0.89, speed: 0.0031, size: 3.9, trailLength: 15, burstIndex: 1 },
    { id: 20, type: 'BURST', depth: 'mid', pathId: 'tunnelCenter', progress: 0.92, speed: 0.0031, size: 4.1, trailLength: 17, burstIndex: 2 },
    { id: 21, type: 'BURST', depth: 'mid', pathId: 'tunnelCenter', progress: 0.95, speed: 0.0031, size: 3.8, trailLength: 14, burstIndex: 3 },

    // BACKGROUND LAYER (Deeper, smaller, dimmer)
    { id: 22, type: 'ESP', depth: 'bg', pathId: 'tunnelUpper', progress: 0.30, speed: 0.0016, size: 2.7, trailLength: 9 },
    { id: 23, type: 'IKE', depth: 'bg', pathId: 'tunnelUpper', progress: 0.65, speed: 0.0015, size: 2.9, trailLength: 11 },
    { id: 24, type: 'ESP', depth: 'bg', pathId: 'tunnelCenter', progress: 0.05, speed: 0.0017, size: 2.8, trailLength: 10 },
    { id: 25, type: 'CTRL', depth: 'bg', pathId: 'tunnelCenter', progress: 0.50, speed: 0.0020, size: 2.5, trailLength: 8 },
    { id: 26, type: 'ESP', depth: 'bg', pathId: 'tunnelLower', progress: 0.40, speed: 0.0016, size: 2.9, trailLength: 9 },
    { id: 27, type: 'ESP', depth: 'bg', pathId: 'ingress', progress: 0.48, speed: 0.0018, size: 2.8, trailLength: 10 },
    { id: 28, type: 'ESP', depth: 'bg', pathId: 'egressUpper', progress: 0.80, speed: 0.0019, size: 2.7, trailLength: 10 },
  ]);

  // Mouse move handler
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const rect = containerRef.current?.getBoundingClientRect();
    if (!rect) return;

    const normX = ((e.clientX - rect.left) / rect.width) * 2 - 1; // [-1, 1]
    const normY = -(((e.clientY - rect.top) / rect.height) * 2 - 1);

    targetMouseRef.current.x = Math.max(-1, Math.min(1, normX));
    targetMouseRef.current.y = Math.max(-1, Math.min(1, normY));
  }, []);

  const handleMouseLeave = useCallback(() => {
    targetMouseRef.current.x = 0;
    targetMouseRef.current.y = 0;
    setHoveredMechanism(null);
  }, []);

  // Animation Loop (Parallax Lerp + Packets + ThinkingOrb Canvas)
  useEffect(() => {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let lastTime = performance.now();
    let burstTimer = 0;

    const render = (now: number) => {
      const dt = Math.min((now - lastTime) / 1000, 0.1);
      lastTime = now;

      // Parallax Damping Factor (max 3-5 deg rotation)
      if (!prefersReducedMotion) {
        const factor = 0.06;
        currentMouseRef.current.x += (targetMouseRef.current.x - currentMouseRef.current.x) * factor;
        currentMouseRef.current.y += (targetMouseRef.current.y - currentMouseRef.current.y) * factor;

        setMouseParallax({
          x: currentMouseRef.current.x,
          y: currentMouseRef.current.y,
        });

        // Core proximity multiplier
        const distFromCore = Math.hypot(currentMouseRef.current.x - 0.35, currentMouseRef.current.y);
        const act = Math.max(1.0, Math.min(2.2, 1.0 + (1 - distFromCore) * 1.3));
        setCoreActivity(act);
      }

      burstTimer += dt;
      if (burstTimer > 4.5) {
        setBurstCycle((prev) => prev + 1);
        burstTimer = 0;
      }

      // Packet progress across curved trajectories
      packetsRef.current.forEach((pkt) => {
        let speed = pkt.speed;

        // Packet slows momentarily in Cryptographic Aperture (progress ~ 0.44-0.56 in tunnelCenter)
        if (pkt.pathId === 'tunnelCenter' && pkt.progress > 0.44 && pkt.progress < 0.56) {
          speed *= 0.52;
        }

        if (!prefersReducedMotion) {
          pkt.progress += speed * (isTransitioning ? 3.0 : 1.0);
          if (pkt.progress > 1.0) pkt.progress = 0.0;
        }
      });

      // ThinkingOrb Canvas Rendering around the 32px Core
      const canvas = orbCanvasRef.current;
      if (canvas) {
        const ctx = canvas.getContext('2d');
        if (ctx) {
          ctx.clearRect(0, 0, canvas.width, canvas.height);

          const orbCenterX = canvas.width / 2;
          const orbCenterY = canvas.height / 2;
          const t = now * 0.001;
          const act = prefersReducedMotion ? 0.3 : (hoveredMechanism === 'core' ? 1.8 : coreActivity);

          const nodePositions = constellationNodes.map((node) => {
            const angle = node.baseAngle + t * node.speed * act;
            const cosT = Math.cos(node.tilt);
            const sinT = Math.sin(node.tilt);
            const unrotX = Math.cos(angle) * node.radiusX;
            const unrotY = Math.sin(angle) * node.radiusY;

            return {
              x: orbCenterX + (unrotX * cosT - unrotY * sinT),
              y: orbCenterY + (unrotX * sinT + unrotY * cosT),
              size: node.size,
              colorType: node.colorType,
            };
          });

          // Dynamic connecting links
          const connectThreshold = 34 * (act > 1.3 ? 1.25 : 1.0);
          for (let i = 0; i < nodePositions.length; i++) {
            for (let j = i + 1; j < nodePositions.length; j++) {
              const dx = nodePositions[i].x - nodePositions[j].x;
              const dy = nodePositions[i].y - nodePositions[j].y;
              const dist = Math.hypot(dx, dy);

              if (dist < connectThreshold) {
                const alpha = Math.max(0, (1 - dist / connectThreshold) * 0.7 * act);
                const lineStroke =
                  nodePositions[i].colorType === 'copper' || nodePositions[j].colorType === 'copper'
                    ? isLight
                      ? `rgba(185, 101, 62, ${alpha})`
                      : `rgba(196, 122, 82, ${alpha})`
                    : isLight
                    ? `rgba(94, 142, 125, ${alpha})`
                    : `rgba(143, 184, 168, ${alpha})`;

                ctx.beginPath();
                ctx.moveTo(nodePositions[i].x, nodePositions[i].y);
                ctx.lineTo(nodePositions[j].x, nodePositions[j].y);
                ctx.strokeStyle = lineStroke;
                ctx.lineWidth = 0.8;
                ctx.stroke();

                // Subtle traveling telemetry spark
                const pulseT = (t * 1.5 + i + j) % 1;
                const px = nodePositions[i].x + (nodePositions[j].x - nodePositions[i].x) * pulseT;
                const py = nodePositions[i].y + (nodePositions[j].y - nodePositions[i].y) * pulseT;
                ctx.beginPath();
                ctx.arc(px, py, 1.0, 0, Math.PI * 2);
                ctx.fillStyle = isLight ? colors.copper : '#FFFFFF';
                ctx.fill();
              }
            }
          }

          // Draw Nodes
          nodePositions.forEach((pos) => {
            const nodeColor =
              pos.colorType === 'copper'
                ? colors.copper
                : pos.colorType === 'mint'
                ? colors.mint
                : colors.graphite;

            ctx.beginPath();
            ctx.arc(pos.x, pos.y, pos.size, 0, Math.PI * 2);
            ctx.fillStyle = nodeColor;
            ctx.shadowBlur = act > 1.2 ? 3 : 1;
            ctx.shadowColor = nodeColor;
            ctx.fill();
            ctx.shadowBlur = 0;
          });
        }
      }

      animFrameRef.current = requestAnimationFrame(render);
    };

    animFrameRef.current = requestAnimationFrame(render);
    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [coreActivity, isLight, colors, isTransitioning, constellationNodes, hoveredMechanism]);

  // Parallax Multipliers (max 3-5 deg camera, with depth expansion)
  const bgShiftX = mouseParallax.x * 10;
  const bgShiftY = -mouseParallax.y * 6;
  const tunnelEntranceShiftX = mouseParallax.x * 12;
  const tunnelEntranceShiftY = -mouseParallax.y * 8;
  const tunnelShiftX = mouseParallax.x * 22;
  const tunnelShiftY = -mouseParallax.y * 14;
  const coreShiftX = mouseParallax.x * 28;
  const coreShiftY = -mouseParallax.y * 18;
  const annoShiftX = mouseParallax.x * 32;
  const annoShiftY = -mouseParallax.y * 20;

  // Helper evaluator for smooth cubic Bezier curves: B(t) for t in [0, 1]
  const evalCubicBezier = (
    p0: { x: number; y: number },
    c1: { x: number; y: number },
    c2: { x: number; y: number },
    p3: { x: number; y: number },
    t: number
  ) => {
    const u = 1 - t;
    const tt = t * t;
    const uu = u * u;
    const uuu = uu * u;
    const ttt = tt * t;
    return {
      x: uuu * p0.x + 3 * uu * t * c1.x + 3 * u * tt * c2.x + ttt * p3.x,
      y: uuu * p0.y + 3 * uu * t * c1.y + 3 * u * tt * c2.y + ttt * p3.y,
    };
  };

  // Continuous organic packet trajectory evaluator
  const getPacketPos = (pkt: TelemetryPacket) => {
    const t = pkt.progress;
    if (pkt.pathId === 'ingress') {
      // Emerges smoothly from behind text (X_START = 220) -> First Oval (520) -> IKE Chamber (780)
      return evalCubicBezier(
        { x: X_START, y: CY },
        { x: 420, y: 345 },
        { x: 620, y: 348 },
        { x: 780, y: 350 },
        t
      );
    } else if (pkt.pathId === 'tunnelUpper') {
      // Follows upper interior streamline with organic cubic curvature from behind text
      if (t < 0.5) {
        return evalCubicBezier(
          { x: X_START, y: 342 },
          { x: 440, y: 310 },
          { x: 700, y: 220 },
          { x: CX, y: 220 },
          t * 2
        );
      } else {
        return evalCubicBezier(
          { x: CX, y: 220 },
          { x: 1050, y: 220 },
          { x: 1220, y: 245 },
          { x: 1380, y: 255 },
          (t - 0.5) * 2
        );
      }
    } else if (pkt.pathId === 'tunnelCenter') {
      // Traverses the central organic waveguide axis from behind text through Core to ESP egress
      if (t < 0.5) {
        return evalCubicBezier(
          { x: X_START, y: CY },
          { x: 440, y: 346 },
          { x: 700, y: 348 },
          { x: CX, y: CY },
          t * 2
        );
      } else {
        return evalCubicBezier(
          { x: CX, y: CY },
          { x: 1050, y: 353 },
          { x: 1220, y: 349 },
          { x: 1380, y: CY },
          (t - 0.5) * 2
        );
      }
    } else if (pkt.pathId === 'tunnelLower') {
      // Follows lower interior streamline with organic cubic curvature from behind text
      if (t < 0.5) {
        return evalCubicBezier(
          { x: X_START, y: 358 },
          { x: 440, y: 390 },
          { x: 700, y: 480 },
          { x: CX, y: 480 },
          t * 2
        );
      } else {
        return evalCubicBezier(
          { x: CX, y: 480 },
          { x: 1050, y: 480 },
          { x: 1220, y: 455 },
          { x: 1380, y: 445 },
          (t - 0.5) * 2
        );
      }
    } else if (pkt.pathId === 'egressUpper') {
      // Smooth branching streamline: Core (890, 350) -> Traffic ML (1280, 240)
      return evalCubicBezier(
        { x: CX, y: CY },
        { x: 1020, y: CY },
        { x: 1160, y: 250 },
        { x: 1280, y: 240 },
        t
      );
    } else if (pkt.pathId === 'egressLower') {
      // Smooth branching streamline: Core (890, 350) -> Risk Endpoint (1280, 460)
      return evalCubicBezier(
        { x: CX, y: CY },
        { x: 1020, y: CY },
        { x: 1160, y: 450 },
        { x: 1280, y: 460 },
        t
      );
    } else {
      // Reverse flow (Gateway return telemetry curving gently back through lower chamber)
      return evalCubicBezier(
        { x: 1260, y: 365 },
        { x: 1080, y: 368 },
        { x: 780, y: 362 },
        { x: 480, y: 360 },
        t
      );
    }
  };

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={`relative w-full h-full min-h-[580px] lg:min-h-[680px] select-none pointer-events-auto transition-transform duration-700 ${
        isTransitioning ? 'scale-125 opacity-90' : ''
      }`}
      style={{
        background: 'transparent', // 100% TRANSPARENT: NO CARD, NO BLACK RECTANGLE
      }}
    >
      <svg
        className="w-full h-full block overflow-visible"
        viewBox="0 0 1400 700"
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          {/* 
            =========================================================================
            ORGANIC CONTINUOUS 3D TUNNEL VOLUME GRADIENT
            Starts behind the text at X_START = 220 (2-4% opacity), expands smoothly
            as it emerges past the text, reaches 4-7% in the throat, 5-9% at Core (890).
            =========================================================================
          */}
          <linearGradient id="organicTunnelVolumeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            {/* Behind text (X = 220 to 420): subtle 2-3% opacity */}
            <stop offset="0%" stopColor={colors.copper} stopOpacity={isLight ? '0.015' : '0.025'} />
            <stop offset="18%" stopColor={colors.copper} stopOpacity={isLight ? '0.025' : '0.035'} />
            {/* Emerging past text & approaching First Oval (X ~ 520): 3.5-4.5% */}
            <stop offset="28%" stopColor={colors.copper} stopOpacity={isLight ? '0.035' : '0.048'} />
            {/* Middle throat & IKE (X ~ 660 to 780): 4.5-6.5% */}
            <stop offset="42%" stopColor={colors.mint} stopOpacity={isLight ? '0.045' : '0.065'} />
            {/* Central IPsec Core (CX = 890): 6-8.5% */}
            <stop offset="58%" stopColor={colors.copper} stopOpacity={isLight ? '0.06' : '0.085'} />
            {/* ESP Corridor (X ~ 1080): 5-7% */}
            <stop offset="78%" stopColor={colors.mint} stopOpacity={isLight ? '0.05' : '0.07'} />
            {/* Far right egress: 3-4% */}
            <stop offset="100%" stopColor={colors.copper} stopOpacity={isLight ? '0.025' : '0.038'} />
          </linearGradient>

          {/* Upper Organic Wall Sweep (Soft Fresnel ceiling glow) */}
          <linearGradient id="organicTopWallGrad" x1="0%" y1="100%" x2="0%" y2="0%">
            <stop offset="0%" stopColor={colors.tunnelStroke} stopOpacity="0.0" />
            <stop offset="100%" stopColor={colors.copper} stopOpacity={isLight ? '0.045' : '0.075'} />
          </linearGradient>

          {/* Lower Organic Wall Sweep (Soft Fresnel floor glow) */}
          <linearGradient id="organicBottomWallGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor={colors.tunnelStroke} stopOpacity="0.0" />
            <stop offset="100%" stopColor={colors.mint} stopOpacity={isLight ? '0.04' : '0.07'} />
          </linearGradient>

          {/* Subtle Tunnel Origin Aura (Soft atmospheric glow behind the text) */}
          <radialGradient id="tunnelOriginGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={colors.copper} stopOpacity={isLight ? '0.08' : '0.12'} />
            <stop offset="60%" stopColor={colors.mint} stopOpacity={isLight ? '0.02' : '0.04'} />
            <stop offset="100%" stopColor={colors.copper} stopOpacity="0.0" />
          </radialGradient>

          {/* Volumetric Chamber Core Glow */}
          <radialGradient id="restoredCoreAura" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={colors.copper} stopOpacity={isLight ? '0.28' : '0.38'} />
            <stop offset="45%" stopColor={colors.copper} stopOpacity={isLight ? '0.05' : '0.10'} />
            <stop offset="100%" stopColor={colors.copper} stopOpacity="0.0" />
          </radialGradient>

          {/* Telemetry Trace to #pipeline */}
          <linearGradient id="restoredPipelineTrace" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor={colors.copper} stopOpacity="0.75" />
            <stop offset="50%" stopColor={colors.mint} stopOpacity="0.5" />
            <stop offset="100%" stopColor={colors.copper} stopOpacity="0.15" />
          </linearGradient>
        </defs>

        {/* 
          ===========================================================================
          PLANE 1: 3D ENVIRONMENTAL GROUND PERSPECTIVE GRID (PARALLAX 0.1X)
          Floor rays radiating toward CX (890), grounded back to tunnel origin (220).
          ===========================================================================
        */}
        <g
          className="environmental-grid"
          transform={`translate(${bgShiftX}, ${bgShiftY})`}
          stroke={colors.gridSubtle}
          strokeWidth="0.75"
        >
          {/* Floor perspective rays */}
          <line x1="220" y1="680" x2="790" y2="310" opacity="0.18" />
          <line x1="440" y1="680" x2="810" y2="310" opacity="0.22" />
          <line x1="660" y1="680" x2="850" y2="310" opacity="0.32" />
          <line x1="890" y1="680" x2="890" y2="310" stroke={colors.copperTrace} strokeDasharray="4 4" opacity="0.45" />
          <line x1="1120" y1="680" x2="930" y2="310" opacity="0.35" />
          <line x1="1340" y1="680" x2="970" y2="310" opacity="0.25" />

          {/* Transverse floor arcs */}
          <line x1="200" y1="510" x2="1380" y2="510" strokeDasharray="3 4" opacity="0.25" />
          <line x1="200" y1="590" x2="1380" y2="590" opacity="0.30" />
          <line x1="200" y1="660" x2="1380" y2="660" strokeDasharray="5 5" opacity="0.35" />

          {/* Floor drop guide grounding the main core */}
          <line x1={CX} y1={CY + 235} x2={CX} y2={640} strokeDasharray="2 3" opacity="0.4" />
          <circle cx={CX} cy={640} r="2" fill={colors.copper} opacity="0.6" />
        </g>

        {/* 
          ===========================================================================
          PLANE 2: THE CONTINUOUS ORGANIC 3D IPSEC TUNNEL ENVIRONMENT (PARALLAX 0.4X)
          REFINED CONTINUOUS GEOMETRY:
          - Originates BEHIND the hero headline at X_START = 220
          - Continuous upper and lower walls emerge from behind the text (X ~ 420-440)
          - Translucent tunnel volume already exists behind and between the words
          - FIRST OVAL sits deeper inside the tunnel at X = 520 (NOT the tunnel mouth!)
          - Visible unobstructed tunnel space between the text and the first oval
          - 6 consecutive cross-sectional elliptical rings inside the continuous tube
          - 100% continuous cubic Bezier curvature with horizontal tangents at Core
          - Dual-layer soft edges on rings and walls (primary + atmospheric halo)
          - Zero straight diagonal edges, zero trapezoidal angles, zero sharp vertices
          ===========================================================================
        */}
        <g
          className="funnel-ipsec-tunnel"
          transform={`translate(${tunnelShiftX}, ${tunnelShiftY})`}
        >
          {/* Soft atmospheric origin glow behind the text */}
          <ellipse
            cx={X_START + 40}
            cy={CY}
            rx="50"
            ry="28"
            fill="url(#tunnelOriginGlow)"
            opacity="0.6"
          />

          {/* 
            =========================================================================
            2.1: MAIN CONTINUOUS TRANSLUCENT TUBE BODY (INFLATED ORGANIC VOLUME)
            Constructed entirely from smooth cubic Bezier splines and elliptic arcs:
            - Starts behind text: (220, 342) -> (890, 115) -> (1420, 158)
            - Egress arc: (1420, 158) -> (1420, 542)
            - Lower wall: (1420, 542) -> (890, 585) -> (220, 358)
            - Origin arc behind text: (220, 358) -> (220, 342)
            =========================================================================
          */}
          <path
            d={`M ${X_START} 342 C 380 335, 680 115, ${CX} 115 C 1050 115, 1240 142, 1420 158 A 52 192 0 0 1 1420 542 C 1240 558, 1050 585, ${CX} 585 C 680 585, 380 365, ${X_START} 358 A 8 8 0 0 1 ${X_START} 342 Z`}
            fill="url(#organicTunnelVolumeGrad)"
            stroke="none"
            opacity={isLight ? 0.8 : 0.9}
          />

          {/* Upper Curved Wall Border (Subtle continuous spline from behind text) */}
          <path
            d={`M ${X_START} 342 C 380 335, 680 115, ${CX} 115 C 1050 115, 1240 142, 1420 158`}
            fill="none"
            stroke={colors.copper}
            strokeWidth="0.8"
            strokeOpacity={isLight ? 0.4 : 0.5}
          />

          {/* Lower Curved Wall Border (Subtle continuous spline from behind text) */}
          <path
            d={`M ${X_START} 358 C 380 365, 680 585, ${CX} 585 C 1050 585, 1240 558, 1420 542`}
            fill="none"
            stroke={colors.mint}
            strokeWidth="0.8"
            strokeOpacity={isLight ? 0.4 : 0.5}
          />

          {/* Upper Curved Wall Fresnel Sweep (Ceiling perspective depth) */}
          <path
            d={`M ${X_START} 342 C 380 335, 680 115, ${CX} 115 C 1050 115, 1240 142, 1420 158 A 45 40 0 0 1 1420 195 C 1240 178, 1050 150, ${CX} 150 C 680 150, 380 348, ${X_START} 348 Z`}
            fill="url(#organicTopWallGrad)"
            stroke="none"
            opacity="0.85"
          />

          {/* Lower Curved Wall Fresnel Sweep (Floor perspective depth) */}
          <path
            d={`M ${X_START} 358 C 380 365, 680 585, ${CX} 585 C 1050 585, 1240 558, 1420 542 A 45 40 0 0 1 1420 505 C 1240 522, 1050 550, ${CX} 550 C 680 550, 380 352, ${X_START} 352 Z`}
            fill="url(#organicBottomWallGrad)"
            stroke="none"
            opacity="0.85"
          />

          {/* 
            =========================================================================
            2.2: 5 CURVED CONTINUOUS STREAMLINES (WAVEGUIDE RIBS)
            All 5 lines start behind the text at X_START=220, emerge smoothly,
            and converge into the right egress at X=1420.
            =========================================================================
          */}
          <g stroke={colors.tunnelStroke}>
            {/* Streamline 1 (Upper Outer Rib, k = -0.7) */}
            <path
              d={`M ${X_START} 344 C 380 338, 680 185, ${CX} 185 C 1050 185, 1240 204, 1420 215`}
              fill="none"
              strokeWidth="0.65"
              strokeDasharray="6 4"
              opacity="0.4"
            />
            {/* Streamline 2 (Upper Inner Rib, k = -0.3) */}
            <path
              d={`M ${X_START} 348 C 380 345, 680 280, ${CX} 280 C 1050 280, 1240 287, 1420 292`}
              fill="none"
              strokeWidth="0.5"
              opacity="0.3"
            />
            {/* Streamline 3 (Central Waveguide Axis, k = 0) */}
            <path
              d={`M ${X_START} 350 C 380 350, 680 350, ${CX} 350 C 1050 350, 1240 350, 1420 350`}
              fill="none"
              strokeWidth="0.5"
              strokeDasharray="3 4"
              opacity="0.22"
            />
            {/* Streamline 4 (Lower Inner Rib, k = +0.3) */}
            <path
              d={`M ${X_START} 352 C 380 355, 680 420, ${CX} 420 C 1050 420, 1240 413, 1420 408`}
              fill="none"
              strokeWidth="0.5"
              opacity="0.3"
            />
            {/* Streamline 5 (Lower Outer Rib, k = +0.7) */}
            <path
              d={`M ${X_START} 356 C 380 362, 680 515, ${CX} 515 C 1050 515, 1240 496, 1420 485`}
              fill="none"
              strokeWidth="0.65"
              strokeDasharray="6 4"
              opacity="0.4"
            />
          </g>

          {/* 
            =========================================================================
            2.3: 6 CONTINUOUS CROSS-SECTIONAL ELLIPTICAL RINGS WITH DUAL-LAYER EDGES
            Every ring is a slice through the continuous organic tube:
            - Ring 1 (First Oval):    X=520, rx=26, ry=75 (deeper inside tunnel, clear of text)
            - Ring 2 (Throat):        X=660, rx=40, ry=135 (expanding throat)
            - Ring 3 (IKE):           X=780, rx=56, ry=190 (session chamber)
            - Ring 4 (Core):          CX=890, rx=76, ry=235 (central dissection plane - largest)
            - Ring 5 (ESP):           X=1080, rx=68, ry=225 (encapsulation corridor)
            - Ring 6 (Egress):        X=1260, rx=56, ry=200 (traffic intelligence)
            Each ring features a PRIMARY EDGE + SOFT ATMOSPHERIC HALO EDGE.
            =========================================================================
          */}

          {/* RING 1: FIRST CROSS-SECTION OVAL (X=520 - Deeper inside the tunnel, clear of text) */}
          <g>
            <ellipse
              cx="520"
              cy={CY}
              rx="29"
              ry="79"
              fill="none"
              stroke={colors.mint}
              strokeWidth="0.55"
              strokeDasharray="4 3"
              opacity="0.25"
            />
            <ellipse
              cx="520"
              cy={CY}
              rx="26"
              ry="75"
              fill="none"
              stroke={colors.mint}
              strokeWidth="1.0"
              opacity="0.65"
            />
          </g>

          {/* RING 2: SECOND CROSS-SECTION (X=660 - Expanding Throat) */}
          <g>
            <ellipse
              cx="660"
              cy={CY}
              rx="44"
              ry="140"
              fill="none"
              stroke={colors.mint}
              strokeWidth="0.6"
              strokeDasharray="4 3"
              opacity="0.28"
            />
            <ellipse
              cx="660"
              cy={CY}
              rx="40"
              ry="135"
              fill="none"
              stroke={colors.mint}
              strokeWidth="1.1"
              strokeDasharray="5 3"
              opacity="0.65"
            />
          </g>

          {/* RING 3: THIRD CROSS-SECTION (X=780 - IKE / Session Chamber) */}
          <g>
            <ellipse
              cx="780"
              cy={CY}
              rx="60"
              ry="195"
              fill="none"
              stroke={colors.mint}
              strokeWidth="0.6"
              strokeDasharray="6 3"
              opacity="0.3"
            />
            <ellipse
              cx="780"
              cy={CY}
              rx="56"
              ry="190"
              fill="none"
              stroke={colors.mint}
              strokeWidth="1.2"
              opacity="0.75"
            />
          </g>

          {/* RING 4: FOURTH CROSS-SECTION (CX=890 - Central Dissection Plane at Core - LARGEST) */}
          <g>
            <ellipse
              cx={CX}
              cy={CY}
              rx="81"
              ry="241"
              fill="none"
              stroke={colors.copper}
              strokeWidth="0.75"
              strokeDasharray="6 4"
              opacity="0.35"
            />
            <ellipse
              cx={CX}
              cy={CY}
              rx="76"
              ry="235"
              fill="none"
              stroke={colors.copper}
              strokeWidth="1.6"
              opacity="0.95"
            />
          </g>

          {/* RING 5: FIFTH CROSS-SECTION (X=1080 - ESP Encapsulation Corridor) */}
          <g>
            <ellipse
              cx="1080"
              cy={CY}
              rx="72"
              ry="230"
              fill="none"
              stroke={colors.mint}
              strokeWidth="0.6"
              strokeDasharray="4 3"
              opacity="0.25"
            />
            <ellipse
              cx="1080"
              cy={CY}
              rx="68"
              ry="225"
              fill="none"
              stroke={colors.mint}
              strokeWidth="1.2"
              strokeDasharray="5 3"
              opacity="0.7"
            />
          </g>

          {/* RING 6: SIXTH CROSS-SECTION (X=1260 - Traffic ML Egress Rim) */}
          <g>
            <ellipse
              cx="1260"
              cy={CY}
              rx="60"
              ry="205"
              fill="none"
              stroke={colors.copper}
              strokeWidth="0.6"
              strokeDasharray="4 3"
              opacity="0.2"
            />
            <ellipse
              cx="1260"
              cy={CY}
              rx="56"
              ry="200"
              fill="none"
              stroke={colors.copper}
              strokeWidth="1.1"
              opacity="0.55"
            />
          </g>

          {/* 
            =========================================================================
            2.4: 3 SUBTLE TRANSPARENT DEPTH PLANES / APERTURES (IKE, CRYPTO, ESP)
            Embedded as translucent cross-sections of the organic tube.
            =========================================================================
          */}
          {/* Aperture Plane 1: IKE SA Diaphragm (X = 780) */}
          <ellipse
            cx="780"
            cy={CY}
            rx="54"
            ry="185"
            fill={colors.mint}
            fillOpacity={isLight ? 0.03 : 0.045}
            stroke={colors.mint}
            strokeWidth="0.8"
            strokeDasharray="4 3"
            opacity="0.55"
          />

          {/* Aperture Plane 2: Crypto Dissection Diaphragm (CX = 890) */}
          <ellipse
            cx={CX}
            cy={CY}
            rx="74"
            ry="230"
            fill={colors.copper}
            fillOpacity={isLight ? 0.035 : 0.055}
            stroke={colors.copper}
            strokeWidth="0.9"
            opacity="0.6"
          />

          {/* Aperture Plane 3: ESP Encapsulation Diaphragm (X = 1080) */}
          <ellipse
            cx="1080"
            cy={CY}
            rx="64"
            ry="220"
            fill={colors.mint}
            fillOpacity={isLight ? 0.03 : 0.045}
            stroke={colors.mint}
            strokeWidth="0.8"
            strokeDasharray="4 3"
            opacity="0.5"
          />

          {/* Radial Ambient Core Glow */}
          <circle cx={CX} cy={CY} r="125" fill="url(#restoredCoreAura)" />

          {/* 4 Intersecting 3D Gimbal Orbital Rings around Core */}
          {/* Ring 1: Tilted IKE SA Orbit (Copper - 24 deg) */}
          <ellipse
            cx={CX}
            cy={CY}
            rx="105"
            ry="45"
            fill="none"
            stroke={colors.copper}
            strokeWidth="1.2"
            opacity="0.8"
            transform={`rotate(${24 + mouseParallax.x * 6} ${CX} ${CY})`}
          />

          {/* Ring 2: Counter-Tilted ESP Child SA Orbit (Mint - -34 deg) */}
          <ellipse
            cx={CX}
            cy={CY}
            rx="140"
            ry="58"
            fill="none"
            stroke={colors.mint}
            strokeWidth="1.0"
            strokeDasharray="5 3"
            opacity="0.75"
            transform={`rotate(${-34 - mouseParallax.y * 7} ${CX} ${CY})`}
          />

          {/* Ring 3: Deep Perspective Ellipse (Amber - 68 deg) */}
          <ellipse
            cx={CX}
            cy={CY}
            rx="175"
            ry="70"
            fill="none"
            stroke={isLight ? '#B88828' : '#D7A84D'}
            strokeWidth="0.85"
            strokeDasharray="3 4"
            opacity="0.6"
            transform={`rotate(${68 + mouseParallax.x * 5} ${CX} ${CY})`}
          />

          {/* Ring 4: Outer Ephemeral Vector (Copper trace - -18 deg) */}
          <ellipse
            cx={CX}
            cy={CY}
            rx="155"
            ry="54"
            fill="none"
            stroke={colors.copperTrace}
            strokeWidth="0.8"
            opacity="0.45"
            transform={`rotate(${-18 - mouseParallax.y * 5} ${CX} ${CY})`}
          />

          {/* 
            =========================================================================
            6 EMBEDDED IPSEC MECHANISMS (STRUCTURAL DETAILS INSIDE TUNNEL)
            =========================================================================
          */}

          {/* MECHANISM 1: IKE GATE (X = 700) */}
          <g
            className="cursor-pointer"
            onMouseEnter={() => setHoveredMechanism('ike')}
            onMouseLeave={() => setHoveredMechanism(null)}
          >
            <line
              x1="690"
              y1="280"
              x2="690"
              y2="420"
              stroke={colors.copper}
              strokeWidth={hoveredMechanism === 'ike' ? '1.4' : '1.0'}
              strokeDasharray="3 3"
              opacity={hoveredMechanism === 'ike' ? '0.9' : '0.65'}
            />
            <line
              x1="710"
              y1="280"
              x2="710"
              y2="420"
              stroke={colors.mint}
              strokeWidth={hoveredMechanism === 'ike' ? '1.4' : '1.0'}
              strokeDasharray="3 3"
              opacity={hoveredMechanism === 'ike' ? '0.9' : '0.65'}
            />
            {/* Subtle packet cross-exchange dashes */}
            <line x1="690" y1="330" x2="710" y2="330" stroke={colors.copper} strokeWidth="0.8" strokeDasharray="2 2" opacity="0.6" />
            <line x1="690" y1="370" x2="710" y2="370" stroke={colors.mint} strokeWidth="0.8" strokeDasharray="2 2" opacity="0.6" />
          </g>

          {/* MECHANISM 2: SESSION / CHILD-SA (X = 780) */}
          <g>
            <path
              d="M 750 330 C 770 330, 778 345, 785 350 C 792 355, 800 370, 820 370"
              fill="none"
              stroke={colors.mint}
              strokeWidth="1.0"
              opacity="0.65"
            />
            <path
              d="M 750 370 C 770 370, 778 355, 785 350 C 792 345, 800 330, 820 330"
              fill="none"
              stroke={colors.mint}
              strokeWidth="1.0"
              opacity="0.65"
            />
            {/* Association Diamond Marker */}
            <polygon points="785,346 789,350 785,354 781,350" fill={colors.mint} opacity="0.8" />
          </g>

          {/* MECHANISM 3: CRYPTOGRAPHIC APERTURE & REDUCED IPSEC ENGINE (CX = 890, CY = 350) */}
          <g
            transform={`translate(${CX}, ${CY}) scale(${1 + (coreActivity - 1) * 0.08})`}
            className="cursor-pointer transition-transform duration-100 ease-out"
            onMouseEnter={() => setHoveredMechanism('core')}
            onMouseLeave={() => setHoveredMechanism(null)}
          >
            {/* Cryptographic Aperture: Nested geometric facets */}
            <polygon points="0,-28 28,0 0,28 -28,0" fill="none" stroke={colors.copper} strokeWidth="0.8" opacity="0.45" />
            <polygon points="0,-36 36,0 0,36 -36,0" fill="none" stroke={colors.mint} strokeWidth="0.7" strokeDasharray="3 3" opacity="0.35" />
            <polygon points="-22,-22 22,-22 22,22 -22,22" fill="none" stroke={colors.copperTrace} strokeWidth="0.75" opacity="0.3" />

            {/* Small 32x32px Central Engine */}
            <rect
              x="-16"
              y="-16"
              width="32"
              height="32"
              fill={colors.coreBg}
              stroke={colors.coreBorder}
              strokeWidth="1.6"
              rx="2"
            />

            {/* Corner Tech Fittings */}
            <g stroke={colors.copper} strokeWidth="1.2">
              <path d="M -16 -10 L -16 -16 L -10 -16" fill="none" />
              <path d="M 10 -16 L 16 -16 L 16 -10" fill="none" />
              <path d="M 16 10 L 16 16 L 10 16" fill="none" />
              <path d="M -10 16 L -16 16 L -16 10" fill="none" />
            </g>

            {/* Concentric Breathing Diamond ◇ */}
            <polygon
              points="0,-8 8,0 0,8 -8,0"
              fill="none"
              stroke={colors.copper}
              strokeWidth="1.1"
            />
            <polygon
              points="0,-3.5 3.5,0 0,3.5 -3.5,0"
              fill={colors.copper}
              opacity="0.9"
            />

            <text
              x="0"
              y="24"
              textAnchor="middle"
              className="font-mono text-[6px] uppercase tracking-wider font-semibold fill-current"
              fill={colors.copper}
            >
              IPSEC ENGINE
            </text>
          </g>

          {/* ThinkingOrb Constellation (Canvas scaled to fit 32px core inside tunnel) */}
          <foreignObject
            x={CX - 80}
            y={CY - 80}
            width="160"
            height="160"
            className="pointer-events-none overflow-visible"
          >
            <canvas
              ref={orbCanvasRef}
              width={160}
              height={160}
              className="w-full h-full block"
            />
          </foreignObject>

          {/* MECHANISM 4: ESP ENCAPSULATION CORRIDOR (X = 960 to 1100) */}
          <g>
            <line x1="940" y1="328" x2="1140" y2="328" stroke={colors.mint} strokeWidth="0.8" strokeDasharray="5 3" opacity="0.6" />
            <line x1="940" y1="372" x2="1140" y2="372" stroke={colors.mint} strokeWidth="0.8" strokeDasharray="5 3" opacity="0.6" />
          </g>

          {/* MECHANISM 5: TRAFFIC ANALYSIS REGION (X = 1140 to 1280) */}
          <g
            className="cursor-pointer"
            onMouseEnter={() => setHoveredMechanism('traffic')}
            onMouseLeave={() => setHoveredMechanism(null)}
          >
            <path
              d={`M 1140 ${CY} C 1190 ${CY - 40}, 1230 ${CY - 85}, 1280 ${CY - 100}`}
              fill="none"
              stroke={colors.copper}
              strokeWidth={hoveredMechanism === 'traffic' ? '1.4' : '1.1'}
              opacity={hoveredMechanism === 'traffic' ? '0.95' : '0.75'}
            />
            <path
              d={`M 1140 ${CY} C 1200 ${CY}, 1250 ${CY}, 1310 ${CY}`}
              fill="none"
              stroke={colors.graphite}
              strokeWidth="0.8"
              strokeDasharray="4 3"
              opacity="0.5"
            />
            <path
              d={`M 1140 ${CY} C 1190 ${CY + 40}, 1230 ${CY + 75}, 1280 ${CY + 100}`}
              fill="none"
              stroke={colors.mint}
              strokeWidth={hoveredMechanism === 'traffic' ? '1.3' : '1.0'}
              strokeDasharray="5 3"
              opacity={hoveredMechanism === 'traffic' ? '0.9' : '0.65'}
            />

            {/* Small analytical node at (1280, CY - 100) */}
            <rect x="1277" y={CY - 103} width="6" height="6" fill={colors.coreBg} stroke={colors.copper} strokeWidth="1.1" />
          </g>

          {/* MECHANISM 6: RISK ENDPOINT (Far Right: X = 1280, Y = CY + 100) */}
          <g transform={`translate(1280, ${CY + 100})`}>
            <circle cx="0" cy="0" r="2.2" fill={colors.amber} />
            <circle cx="0" cy="0" r="5" fill="none" stroke={colors.amber} opacity="0.45">
              <animate attributeName="r" values="3.5;6.5;3.5" dur="2.2s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.6;0.1;0.6" dur="2.2s" repeatCount="indefinite" />
            </circle>
          </g>

          {/* Vertical Telemetry Trace down to #pipeline */}
          <g className="pipeline-telemetry-connector">
            <line
              x1={CX}
              y1={CY + 30}
              x2={CX}
              y2={680}
              stroke="url(#restoredPipelineTrace)"
              strokeWidth="1.2"
              strokeDasharray="4 3"
            />
            <circle cx={CX} cy={CY + 80} r="2.2" fill={colors.copper}>
              <animate attributeName="cy" values={`${CY + 30};670`} dur="2.4s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0;1;0" dur="2.4s" repeatCount="indefinite" />
            </circle>
          </g>
        </g>

        {/* 
          ===========================================================================
          PLANE 3: DYNAMIC MULTI-DEPTH PACKET STREAMS (28 PACKETS) (PARALLAX 0.55X)
          Background (dim, small) -> Midground (bursts) -> Foreground (crisp, large)
          Packet state transformation: plain dot/diamond before Crypto (X < 890),
          sealed encrypted capsule after Crypto (X >= 890).
          ===========================================================================
        */}
        <g
          className="telemetry-packets-layer"
          transform={`translate(${tunnelShiftX * 0.85}, ${tunnelShiftY * 0.85})`}
        >
          {packetsRef.current.map((pkt) => {
            const { x, y } = getPacketPos(pkt);

            const pktColor =
              pkt.type === 'IKE'
                ? colors.copper
                : pkt.type === 'CTRL'
                ? colors.mint
                : pkt.type === 'BURST' || pkt.type === 'RISK'
                ? colors.amber
                : isLight
                ? colors.graphite
                : colors.bone;

            const opacity = pkt.depth === 'bg' ? 0.45 : pkt.depth === 'mid' ? 0.75 : 0.95;
            const trailDir = pkt.pathId === 'reverse' ? 1 : -1;

            return (
              <g key={pkt.id} transform={`translate(${x}, ${y})`} opacity={opacity}>
                {/* Thin Faint Comet Trail */}
                <line
                  x1={trailDir * pkt.trailLength}
                  y1="0"
                  x2="0"
                  y2="0"
                  stroke={pktColor}
                  strokeWidth={pkt.depth === 'fg' ? '1.3' : '0.9'}
                  strokeOpacity="0.35"
                />

                {/* Packet body transformation:
                    - Plain dot / diamond before Crypto Core (x < CX = 890)
                    - Sealed encrypted capsule after Crypto Core (x >= CX = 890)
                */}
                {x < CX ? (
                  <g>
                    <circle cx="0" cy="0" r={pkt.size * 0.45} fill={pktColor} />
                    <polygon
                      points={`0,-${pkt.size * 0.5} ${pkt.size * 0.75},0 0,${pkt.size * 0.5} -${pkt.size * 0.75},0`}
                      fill={pktColor}
                      opacity="0.85"
                    />
                  </g>
                ) : (
                  <g>
                    {/* Sealed ESP Capsule Shape */}
                    <rect
                      x={-pkt.size * 0.65}
                      y={-pkt.size * 0.4}
                      width={pkt.size * 1.3}
                      height={pkt.size * 0.8}
                      fill={pktColor}
                      rx="1"
                      opacity="0.9"
                    />
                    <line
                      x1={-pkt.size * 0.25}
                      y1={-pkt.size * 0.4}
                      x2={-pkt.size * 0.25}
                      y2={pkt.size * 0.4}
                      stroke={isLight ? colors.bg : '#0B0C0D'}
                      strokeWidth="0.6"
                      opacity="0.7"
                    />
                  </g>
                )}
              </g>
            );
          })}
        </g>

        {/* 
          ===========================================================================
          PLANE 4: EXACTLY 11 USEFUL TECHNICAL LABELS (PARALLAX 0.7X)
          Sitting cleanly around the organic tunnel; ALL positioned at X >= 680.
          Connected via smooth aerodynamic curved leader lines (avoiding sharp corners).
          ZERO overlap with the headline area (X <= 480).
          1. IKEv2 SA  2. IKE_AUTH  3. CHILD-SA  4. AES-256-GCM  5. PFS ACTIVE
          6. DH GROUP 19  7. ESP  8. ESP_ENCRYPT  9. SPI: 0x9B42A1EF  10. TRAFFIC ML  11. RISK
          ===========================================================================
        */}
        <g
          className="environmental-labels-layer pointer-events-none"
          transform={`translate(${annoShiftX}, ${annoShiftY})`}
        >
          {/* 1. IKEv2 SA (Near IKE Gate: 680, 240) */}
          <g transform="translate(680, 240)">
            <circle cx="0" cy="0" r="1.7" fill={colors.copper} />
            <path d="M 0 0 C -8 -6, -18 -14, -36 -14 L -58 -14" fill="none" stroke={colors.copper} strokeWidth="0.8" opacity="0.75" />
            <text x="-58" y="-18" className="font-mono text-[7.5px] font-bold fill-current" fill={colors.copper}>
              IKEv2 SA
            </text>
          </g>

          {/* 2. IKE_AUTH (Near IKE Lower Gate: 680, 450) */}
          <g transform="translate(680, 450)">
            <circle cx="0" cy="0" r="1.6" fill={colors.mint} />
            <path d="M 0 0 C 6 6, 12 14, 28 14 L 56 14" fill="none" stroke={colors.mint} strokeWidth="0.8" opacity="0.65" />
            <text x="18" y="10" className="font-mono text-[7px] font-semibold fill-current" fill={colors.mint}>
              IKE_AUTH
            </text>
          </g>

          {/* 3. CHILD-SA (Near Session Chamber: 770, 230) */}
          <g transform="translate(770, 230)">
            <circle cx="0" cy="0" r="1.7" fill={colors.mint} />
            <path d="M 0 0 C 6 -6, 12 -14, 28 -14 L 58 -14" fill="none" stroke={colors.mint} strokeWidth="0.8" opacity="0.75" />
            <text x="18" y="-18" className="font-mono text-[7.5px] font-bold fill-current" fill={colors.mint}>
              CHILD-SA
            </text>
          </g>

          {/* 4. AES-256-GCM (Core Top: 890, 160) */}
          <g transform="translate(890, 160)">
            <circle cx="0" cy="0" r="1.9" fill={colors.copper} />
            <path d="M 0 0 C 8 -8, 16 -16, 36 -16 L 80 -16" fill="none" stroke={colors.copper} strokeWidth="0.85" opacity="0.85" />
            <text x="20" y="-20" className="font-mono text-[8px] font-bold fill-current" fill={colors.copper}>
              AES-256-GCM
            </text>
          </g>

          {/* 5. PFS ACTIVE (Orbital Ring Top: 980, 220) */}
          <g transform="translate(980, 220)">
            <circle cx="0" cy="0" r="1.7" fill={colors.mint} />
            <path d="M 0 0 C 6 -6, 14 -14, 32 -14 L 66 -14" fill="none" stroke={colors.mint} strokeWidth="0.8" opacity="0.75" />
            <text x="18" y="-18" className="font-mono text-[7.5px] font-bold fill-current" fill={colors.mint}>
              PFS ACTIVE
            </text>
          </g>

          {/* 6. DH GROUP 19 (Orbital Ring Bottom: 970, 510) */}
          <g transform="translate(970, 510)">
            <circle cx="0" cy="0" r="1.7" fill={colors.mint} />
            <path d="M 0 0 C 6 6, 14 14, 32 14 L 72 14" fill="none" stroke={colors.mint} strokeWidth="0.8" opacity="0.7" />
            <text x="18" y="10" className="font-mono text-[7px] font-mono fill-current" fill={colors.mint}>
              DH GROUP 19
            </text>
          </g>

          {/* 7. ESP (Tunnel Section: 820, 480) */}
          <g transform="translate(820, 480)">
            <circle cx="0" cy="0" r="1.7" fill={isLight ? colors.graphite : colors.bone} />
            <path d="M 0 0 C -6 6, -12 14, -26 14 L -42 14" fill="none" stroke={colors.graphiteMuted} strokeWidth="0.8" opacity="0.6" />
            <text x="-42" y="10" className="font-mono text-[7.5px] font-bold fill-current" fill={isLight ? colors.graphite : colors.bone}>
              ESP
            </text>
          </g>

          {/* 8. ESP_ENCRYPT (ESP Corridor Top: 1060, 210) */}
          <g transform="translate(1060, 210)">
            <circle cx="0" cy="0" r="1.7" fill={colors.copper} />
            <path d="M 0 0 C 8 -8, 16 -16, 36 -16 L 72 -16" fill="none" stroke={colors.copper} strokeWidth="0.8" opacity="0.75" />
            <text x="20" y="-20" className="font-mono text-[7.5px] font-bold fill-current" fill={colors.copper}>
              ESP_ENCRYPT
            </text>
          </g>

          {/* 9. SPI: 0x9B42A1EF (ESP Corridor Bottom: 1060, 490) */}
          <g transform="translate(1060, 490)">
            <circle cx="0" cy="0" r="1.7" fill={colors.copper} />
            <path d="M 0 0 C 6 6, 14 14, 34 14 L 80 14" fill="none" stroke={colors.copper} strokeWidth="0.8" opacity="0.75" />
            <text x="18" y="10" className="font-mono text-[7px] font-mono fill-current" fill={colors.copper}>
              SPI: 0x9B42A1EF
            </text>
          </g>

          {/* 10. TRAFFIC ML (Far Right Analytical Branch: 1240, 210) */}
          <g transform="translate(1240, 210)">
            <circle cx="0" cy="0" r="1.8" fill={colors.copper} />
            <path d="M 0 0 C 8 -8, 16 -16, 34 -16 L 68 -16" fill="none" stroke={colors.copper} strokeWidth="0.8" opacity="0.8" />
            <text x="20" y="-20" className="font-mono text-[7.5px] font-bold fill-current" fill={colors.copper}>
              TRAFFIC ML
            </text>
          </g>

          {/* 11. RISK (Far Right Endpoint: 1280, 470) */}
          <g transform="translate(1280, 470)">
            <circle cx="0" cy="0" r="1.8" fill={colors.amber} />
            <path d="M 0 0 C 6 6, 12 14, 26 14 L 48 14" fill="none" stroke={colors.amber} strokeWidth="0.8" opacity="0.8" />
            <text x="18" y="10" className="font-mono text-[7.5px] font-bold fill-current" fill={colors.amber}>
              RISK
            </text>
          </g>
        </g>
      </svg>
    </div>
  );
}
