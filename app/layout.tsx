import type { Metadata } from 'next';
import './globals.css';
import { ThemeProvider } from '@/lib/theme/ThemeProvider';

export const metadata: Metadata = {
  title: 'IPsec Sentinel | IPsec Security Intelligence',
  description:
    'An intelligent IPsec platform for automated security analysis, risk assessment, traffic intelligence, compliance monitoring, and actionable security reporting.',
  keywords: [
    'IPsec',
    'IKEv2',
    'ESP',
    'Network Security',
    'Cryptographic Posture',
    'Traffic Intelligence',
    'NTRO',
    'Security Analysis',
    'VPN Inspection',
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              try {
                var params = new URLSearchParams(window.location.search);
                var qTheme = params.get('theme');
                var saved = localStorage.getItem('ipsec_sentinel_theme');
                var t = qTheme || saved || 'dark';
                if (t === 'light') {
                  document.documentElement.classList.add('light');
                  document.documentElement.classList.remove('dark');
                } else {
                  document.documentElement.classList.add('dark');
                  document.documentElement.classList.remove('light');
                }
              } catch (e) {}
            `,
          }}
        />
      </head>
      <body className="min-h-screen bg-sentinel-bg text-sentinel-text antialiased selection:bg-sentinel-copper selection:text-white">
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  );
}
