import { useState } from "react";
import AnalysisDashboard from "./components/AnalysisDashboard";

function App() {
  const [showDashboard, setShowDashboard] = useState(false);

  if (showDashboard) {
    return (
      <AnalysisDashboard
        onBack={() => setShowDashboard(false)}
      />
    );
  }

  return (
    <div className="app">
      <nav className="navbar">
        <div className="logo">
          <span className="logo-mark">◈</span>
          TUNNEL<span>GUARD</span>
        </div>

        <div className="nav-status">
          <span className="status-dot"></span>
          SYSTEM ONLINE
        </div>
      </nav>

      <main className="hero">
        <div className="hero-content">
          <p className="eyebrow">
            AI-POWERED IPsec SECURITY INTELLIGENCE
          </p>

          <h1>
            SEE INSIDE
            <br />
            <span>THE TUNNEL.</span>
          </h1>

          <p className="description">
            Analyze encrypted VPN traffic, detect security weaknesses,
            classify traffic with AI, and turn complex packet captures
            into actionable security intelligence.
          </p>

          <div className="actions">
            <button
              className="primary-btn"
              onClick={() => setShowDashboard(true)}
            >
              ANALYZE PCAP
              <span>→</span>
            </button>

            <button
              className="secondary-btn"
              onClick={() => setShowDashboard(true)}
            >
              VIEW DEMO
            </button>
          </div>
        </div>

        <div className="visual">
          <div className="orb">
            <div className="orb-core"></div>

            <div className="ring ring-1"></div>
            <div className="ring ring-2"></div>
            <div className="ring ring-3"></div>

            <div className="node node-1">IKE</div>
            <div className="node node-2">ESP</div>
            <div className="node node-3">AI</div>
          </div>

          <div className="floating-card card-top">
            <span>SECURITY SCORE</span>
            <strong>100</strong>
            <small>/ 100</small>
          </div>

          <div className="floating-card card-bottom">
            <span>THREAT STATUS</span>
            <strong>LOW RISK</strong>
          </div>
        </div>
      </main>

      <div className="bottom-bar">
        <div>
          <span>01</span>
          PCAP ANALYSIS
        </div>

        <div>
          <span>02</span>
          PROTOCOL INTELLIGENCE
        </div>

        <div>
          <span>03</span>
          AI CLASSIFICATION
        </div>

        <div>
          <span>04</span>
          SECURITY ASSESSMENT
        </div>
      </div>
    </div>
  );
}

export default App;