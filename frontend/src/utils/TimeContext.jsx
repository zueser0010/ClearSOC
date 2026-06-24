import { createContext, useContext, useState } from "react";

const TimeContext = createContext();

export function TimeProvider({ children }) {
  const [globalTime, setGlobalTime] = useState("ALL");
  return (
    <TimeContext.Provider value={{ globalTime, setGlobalTime }}>
      {children}
    </TimeContext.Provider>
  );
}

export function useGlobalTime() {
  return useContext(TimeContext);
}
