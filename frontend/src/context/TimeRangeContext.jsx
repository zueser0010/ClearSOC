import { createContext, useContext, useEffect, useState } from "react";

const TimeRangeContext = createContext(null);

export function TimeRangeProvider({ children }) {
  const [timeRange, setTimeRangeState] = useState(() => {
    return localStorage.getItem("clearsoc_global_time_range") || "24H";
  });

  function setTimeRange(value) {
    localStorage.setItem("clearsoc_global_time_range", value);
    setTimeRangeState(value);
    window.dispatchEvent(new Event("clearsoc_time_range_changed"));
  }

  useEffect(() => {
    function sync() {
      const saved = localStorage.getItem("clearsoc_global_time_range") || "24H";
      setTimeRangeState(saved);
    }

    window.addEventListener("clearsoc_time_range_changed", sync);
    window.addEventListener("storage", sync);

    return () => {
      window.removeEventListener("clearsoc_time_range_changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  return (
    <TimeRangeContext.Provider value={{ timeRange, setTimeRange }}>
      {children}
    </TimeRangeContext.Provider>
  );
}

export function useTimeRange() {
  const ctx = useContext(TimeRangeContext);
  if (!ctx) {
    return { timeRange: "24H", setTimeRange: () => {} };
  }
  return ctx;
}

export function matchesTimeRange(timestamp, timeRange) {
  if (!timestamp || timeRange === "ALL") return true;

  const d = new Date(timestamp);
  if (isNaN(d.getTime())) return true;

  const age = Date.now() - d.getTime();

  if (timeRange === "1H") return age <= 60 * 60 * 1000;
  if (timeRange === "24H") return age <= 24 * 60 * 60 * 1000;
  if (timeRange === "7D") return age <= 7 * 24 * 60 * 60 * 1000;
  if (timeRange === "30D") return age <= 30 * 24 * 60 * 60 * 1000;

  return true;
}
