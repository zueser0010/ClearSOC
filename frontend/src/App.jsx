import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { useEffect } from "react";
import Sidebar from "./components/Sidebar";
import SplashLogin from "./pages/SplashLogin";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Incidents from "./pages/Incidents";
import AttackChains from "./pages/AttackChains";
import Devices from "./pages/Devices";
import AttackMap from "./pages/AttackMap";
import Discover from "./pages/Discover";
import IOCs from "./pages/IOCs";
import Reports from "./pages/Reports";
import Investigation from "./pages/Investigation";
import ComingSoon from "./pages/ComingSoon";
import Suricata from "./pages/Suricata";
import PriorityQueue from "./pages/PriorityQueue";
import Timeline from "./pages/Timeline";
import Mitre from "./pages/Mitre";
import ThreatIntel from "./pages/ThreatIntel";
import Settings from "./pages/Settings";
import { TimeRangeProvider } from "./context/TimeRangeContext";
import "./App.css";
import { TimeProvider } from "./utils/TimeContext";


function SessionManager() {
  const location = useLocation();

  useEffect(() => {
    const resetTimer = () => {
      localStorage.setItem("clearsoc_last_activity", Date.now().toString());
    };

    resetTimer();

    window.addEventListener("click", resetTimer);
    window.addEventListener("keydown", resetTimer);
    window.addEventListener("mousemove", resetTimer);

    const interval = setInterval(() => {
      const last = localStorage.getItem("clearsoc_last_activity");
      if (!last) return;

      const diff = Date.now() - parseInt(last, 10);
      const THREE_MIN = 3 * 60 * 1000;

      if (diff > THREE_MIN && location.pathname !== "/") {
        localStorage.removeItem("clearsoc_last_activity");
        window.location.href = "/";
      }
    }, 10000);

    return () => {
      window.removeEventListener("click", resetTimer);
      window.removeEventListener("keydown", resetTimer);
      window.removeEventListener("mousemove", resetTimer);
      clearInterval(interval);
    };
  }, [location.pathname]);

  return null;
}

function AppLayout({ children }) {
  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">{children}</main>
    </div>
  );
}

export default function App() {
  return (
    <TimeProvider>
    <TimeRangeProvider>
      <BrowserRouter>
      <SessionManager />
      <Routes>
        <Route path="/" element={<SplashLogin />} />
        <Route path="/dashboard" element={<AppLayout><Dashboard /></AppLayout>} />
        <Route path="/alerts" element={<AppLayout><Alerts /></AppLayout>} />
        <Route path="/incidents" element={<AppLayout><Incidents /></AppLayout>} />
        <Route path="/attack-chains" element={<AppLayout><AttackChains /></AppLayout>} />
        <Route path="/devices" element={<AppLayout><Devices /></AppLayout>} />
        <Route path="/attack-map" element={<AppLayout><AttackMap /></AppLayout>} />
        <Route path="/discover" element={<AppLayout><Discover /></AppLayout>} />
        <Route path="/iocs" element={<AppLayout><IOCs /></AppLayout>} />
        <Route path="/reports" element={<AppLayout><Reports /></AppLayout>} />
        <Route path="/investigation" element={<AppLayout><Investigation /></AppLayout>} />
        <Route path="/suricata" element={<AppLayout><Suricata /></AppLayout>} />
        <Route path="/priority" element={<AppLayout><PriorityQueue /></AppLayout>} />
        <Route path="/timeline" element={<AppLayout><Timeline /></AppLayout>} />
        <Route path="/mitre" element={<AppLayout><Mitre /></AppLayout>} />
        <Route path="/threat-intel" element={<AppLayout><ThreatIntel /></AppLayout>} />
        <Route path="/settings" element={<AppLayout><Settings /></AppLayout>} />
        <Route path="/networking" element={<AppLayout><ComingSoon /></AppLayout>} />
        <Route path="/firewall" element={<AppLayout><ComingSoon /></AppLayout>} />
        <Route path="/zeek" element={<AppLayout><ComingSoon /></AppLayout>} />
        <Route path="*" element={<Navigate to="/dashboard" />} />
      </Routes>
      </BrowserRouter>
    </TimeRangeProvider>
    </TimeProvider>
  );
}
