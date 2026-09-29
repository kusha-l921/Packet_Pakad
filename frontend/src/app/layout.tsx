import type { Metadata } from 'next';
import './globals.css';
import { ThemeProvider } from '@/components/layout/ThemeContext';
import { SessionProvider } from '@/context/SessionContext';

export const metadata: Metadata = {
  title: 'Packet Pakad | AI-Powered IPsec Protocol Analyzer',
  description:
    'Enterprise IPsec VPN Security Assessment & Cryptographic Verification Platform',
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
          <SessionProvider>
            {children}
          </SessionProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
