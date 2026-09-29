'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import LandingNavbar from '@/components/landing/LandingNavbar';
import HeroSection from '@/components/landing/HeroSection';
import PipelineVisualization from '@/components/landing/PipelineVisualization';
import CapabilitySection from '@/components/landing/CapabilitySection';
import DataStripSection from '@/components/landing/DataStripSection';
import AssessmentPreview from '@/components/landing/AssessmentPreview';
import DeterministicVsAiSection from '@/components/landing/DeterministicVsAiSection';
import FinalCTA from '@/components/landing/FinalCTA';
import LandingFooter from '@/components/landing/LandingFooter';

export default function LandingPage() {
  const router = useRouter();
  const [isTransitioning, setIsTransitioning] = useState(false);

  const handleOpenConsole = () => {
    setIsTransitioning(true);
    // Smooth tunnel dive duration before route switch
    setTimeout(() => {
      router.push('/dashboard');
    }, 1200);
  };

  return (
    <main className="min-h-screen bg-sentinel-bg text-sentinel-text bg-grid-pattern transition-colors duration-200">
      {/* Top Navigation */}
      <LandingNavbar onOpenConsole={handleOpenConsole} isTransitioning={isTransitioning} />

      {/* Hero with 3D IPsec Tunnel */}
      <HeroSection onOpenConsole={handleOpenConsole} isTransitioning={isTransitioning} />

      {/* 6-Stage Analytical Pipeline */}
      <PipelineVisualization />

      {/* 4 Modular Capability Engines */}
      <CapabilitySection />

      {/* Live Dissection Data Strip & Telemetry */}
      <DataStripSection />

      {/* Realistic Assessment Output Preview */}
      <AssessmentPreview onOpenConsole={handleOpenConsole} />

      {/* Architectural Separation: Deterministic vs AI vs RAG */}
      <DeterministicVsAiSection />

      {/* Final Console Invitation CTA */}
      <FinalCTA onOpenConsole={handleOpenConsole} isTransitioning={isTransitioning} />

      {/* Footer */}
      <LandingFooter />
    </main>
  );
}
