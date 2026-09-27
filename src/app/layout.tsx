import type { Metadata } from 'next';
import './globals.css';
import { ThemeProvider } from '@/components/layout/ThemeContext';

export const metadata: Metadata = {
  title: 'IPSEC SENTINEL | AI-Powered IPsec Protocol Analyzer',
  description:
    'Government & Enterprise IPsec VPN Security Assessment Framework (NTRO Problem Statement 26160)',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-sentinel-bg text-sentinel-text antialiased">
        <ThemeProvider>
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
