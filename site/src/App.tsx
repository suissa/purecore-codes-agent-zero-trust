import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { HomePage } from './pages/HomePage';
import { ArchitecturePage } from './pages/ArchitecturePage';
import { SignalPage } from './pages/SignalPage';
import { DPoPPage } from './pages/DPoPPage';
import { A2APage } from './pages/A2APage';
import { MultiPartyPage } from './pages/MultiPartyPage';
import { ZeroTrustBrokerPage } from './pages/ZeroTrustBrokerPage';
import { TokenManagerPage } from './pages/TokenManagerPage';
import { BloomFilterPage } from './pages/BloomFilterPage';
import { JWKThumbprintPage } from './pages/JWKThumbprintPage';
import { AdversaryPage } from './pages/AdversaryPage';
import { PaperPage } from './pages/PaperPage';
import { useEffect } from 'react';

function ScrollToTop() {
  const { pathname } = useLocation();
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, [pathname]);
  return null;
}

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 ml-64 p-8 md:p-12 lg:p-16 max-w-5xl overflow-y-auto">
        {children}
      </main>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <ScrollToTop />
      <Layout>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/architecture" element={<ArchitecturePage />} />
          <Route path="/signal" element={<SignalPage />} />
          <Route path="/dpop" element={<DPoPPage />} />
          <Route path="/a2a" element={<A2APage />} />
          <Route path="/multiparty" element={<MultiPartyPage />} />
          <Route path="/zero-trust-broker" element={<ZeroTrustBrokerPage />} />
          <Route path="/token-manager" element={<TokenManagerPage />} />
          <Route path="/bloom-filter" element={<BloomFilterPage />} />
          <Route path="/jwk-thumbprint" element={<JWKThumbprintPage />} />
          <Route path="/adversary" element={<AdversaryPage />} />
          <Route path="/paper" element={<PaperPage />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

export default App;
