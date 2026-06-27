import { useEffect, useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Monitor, AlertTriangle, Bell, Link2, RefreshCw, Search, ChevronDown } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import WorldAttackMap from "../components/WorldAttackMap";
import { useGlobalTime } from "../utils/TimeContext";

const API = "http://localhost:8001";
const SEV_COLOR = { CRITICAL:"#ef4444", HIGH:"#f97316", MEDIUM:"#eab308", LOW:"#22c55e", INFO:"#3b82f6" };

const TIME_OPTIONS = [
  { v:"1h", l:"Last 1 Hour" },
  { v:"6h", l:"Last 6 Hours" },
  { v:"24h", l:"Last 24 Hours" },
  { v:"7d", l:"Last 7 Days" },
  { v:"30d", l:"Last 30 Days" },
  { v:"ALL", l:"All Time" },
];

const TIME_MS = { "1h":3600000,"6h":21600000,"24h":86400000,"7d":604800000,"30d":2592000000 };

function filterByTime(items, field, range) {
  if (range === "ALL") return items;
  const now = new Date();
  const limit = TIME_MS[range];
  if (!limit) return items;
  return items.filter(i => {
    const t = new Date(i[field] || "");
    return !isNaN(t) && (now - t) <= limit;
  });
}

export default function Dashboard() {
  const navigate = useNavigate();
  const { globalTime, setGlobalTime } = useGlobalTime();
  const [alerts, setAlerts] = useState([]);
  const [chains, setChains] = useState([]);
  const [rawLogs, setRawLogs] = useState([]);
  const [lastRefresh, setLastRefresh] = useState("");
  const [loading, setLoading] = useState(true);

  async function load() {
    try {
      const [alr, chn, dash] = await Promise.all([
        fetch(`${API}/api/alerts`).then(r => r.json()),
        fetch(`${API}/api/attack-chains`).then(r => r.json()),
        fetch(`${API}/api/dashboard`).then(r => r.json()),
      ]);
      setAlerts(Array.isArray(alr) ? alr : []);
      setChains(Array.isArray(chn) ? chn : []);
      const logs = dash?.devices || [];
      setRawLogs(logs);
      setLastRefresh(new Date().toLocaleTimeString());
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  const fAlerts = useMemo(() => filterByTime(alerts, "time", globalTime), [alerts, globalTime]);
  const fChains = useMemo(() => filterByTime(chains, "time", globalTime), [chains, globalTime]);

  const critical = fAlerts.filter(a => a.severity === "CRITICAL").length;
  const high = fAlerts.filter(a => a.severity === "HIGH").length;
  const medium = fAlerts.filter(a => a.severity === "MEDIUM").length;
  const low = fAlerts.filter(a => !["CRITICAL","HIGH","MEDIUM"].includes(a.severity)).length;
  const total = critical + high + medium + low;

  const hosts = [...new Set(rawLogs.map(l => l.host).filter(Boolean))];
  const totalDevices = hosts.length || 1;

  const riskData = [
    { name:"Critical", value:critical, color:"#ef4444" },
    { name:"High", value:high, color:"#f97316" },
    { name:"Medium", value:medium, color:"#eab308" },
    { name:"Low", value:low, color:"#22c55e" },
  ].filter(d => d.value > 0);

  const trendData = useMemo(() => {
    const days = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const key = d.toLocaleDateString("en-US", { month:"short", day:"numeric" });
      days[key] = 0;
    }
    fAlerts.forEach(a => {
      const t = new Date(a.time);
      if (!isNaN(t)) {
        const key = t.toLocaleDateString("en-US", { month:"short", day:"numeric" });
        if (key in days) days[key]++;
      }
    });
    return Object.entries(days).map(([day, count]) => ({ day, count }));
  }, [fAlerts]);

  const priorityQueue = fChains.filter(c => ["ESCALATE","INVESTIGATE"].includes(c.decision)).slice(0,10);
  const recentChains = fChains.slice(0,8);
  const recentIncidents = fAlerts.slice(0,10);

  if (loading) return <div className="soc-page" style={{color:"#94a3b8",padding:"40px"}}>Loading...</div>;

  return (
    <div className="soc-page" style={{padding:"20px"}}>

      {/* HEADER */}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"20px",flexWrap:"wrap",gap:"12px"}}>
        <div>
          <h1 style={{fontSize:"26px",fontWeight:700,color:"white",margin:0}}>Dashboard</h1>
          <p style={{color:"#64748b",fontSize:"13px",margin:"4px 0 0"}}>Overview & Security Posture</p>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:"10px",flexWrap:"wrap"}}>
          <div style={{display:"flex",alignItems:"center",gap:"8px",background:"rgba(255,255,255,0.04)",border:"1px solid rgba(255,255,255,0.08)",borderRadius:"8px",padding:"8px 12px"}}>
            <Search size={14} color="#64748b"/>
            <span style={{color:"#64748b",fontSize:"13px"}}>Search (Ctrl+/)</span>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:"6px"}}>
            <span style={{width:"8px",height:"8px",borderRadius:"50%",background:"#22c55e",boxShadow:"0 0 6px #22c55e",display:"inline-block"}}/>
            <span style={{color:"#94a3b8",fontSize:"13px"}}>System Status <b style={{color:"white"}}>Online</b></span>
          </div>
          <span style={{color:"#475569",fontSize:"12px"}}>Last refresh: {lastRefresh}</span>
          <select
            value={globalTime}
            onChange={e => setGlobalTime(e.target.value)}
            style={{background:"rgba(56,189,248,0.08)",border:"1px solid rgba(56,189,248,0.25)",color:"#38bdf8",padding:"8px 12px",borderRadius:"8px",fontSize:"13px",cursor:"pointer"}}
          >
            {TIME_OPTIONS.map(o => <option key={o.v} value={o.v}>{o.l}</option>)}
          </select>
          <button onClick={load} style={{display:"flex",alignItems:"center",gap:"6px",background:"rgba(56,189,248,0.1)",border:"1px solid rgba(56,189,248,0.3)",color:"#38bdf8",padding:"8px 14px",borderRadius:"8px",cursor:"pointer",fontSize:"13px"}}>
            <RefreshCw size={14}/> Refresh
          </button>
          <div style={{display:"flex",alignItems:"center",gap:"8px",color:"#94a3b8"}}>
            <div style={{width:"32px",height:"32px",borderRadius:"50%",background:"rgba(56,189,248,0.15)",border:"1px solid rgba(56,189,248,0.3)",display:"flex",alignItems:"center",justifyContent:"center",color:"#38bdf8",fontWeight:700}}>A</div>
            <div style={{display:"flex",flexDirection:"column"}}>
              <b style={{fontSize:"13px",color:"white"}}>Admin</b>
              <span style={{fontSize:"11px",color:"#64748b"}}>SOC Analyst</span>
            </div>
          </div>
        </div>
      </div>

      {/* STAT CARDS */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(7,1fr)",gap:"10px",marginBottom:"16px"}}>
        {[
          { title:"TOTAL DEVICES", value:totalDevices, sub:`Online: ${totalDevices} (100%)`, color:"#38bdf8", icon:<Monitor size={20}/>, path:"/devices" },
          { title:"CRITICAL DEVICES", value:critical, sub:total>0?`${((critical/total)*100).toFixed(1)}% of total`:"Immediate risk", color:"#ef4444", icon:<Shield size={20}/> },
          { title:"HIGH RISK DEVICES", value:high, sub:total>0?`${((high/total)*100).toFixed(1)}% of total`:"Needs review", color:"#f97316", icon:<AlertTriangle size={20}/> },
          { title:"MEDIUM RISK DEVICES", value:medium, sub:total>0?`${((medium/total)*100).toFixed(1)}% of total`:"Monitor", color:"#eab308", icon:<AlertTriangle size={20}/> },
          { title:"LOW RISK DEVICES", value:low, sub:total>0?`${((low/total)*100).toFixed(1)}% of total`:"Normal", color:"#22c55e", icon:<Shield size={20}/> },
          { title:"TOTAL INCIDENTS", value:fAlerts.length, sub:`Today: ${fAlerts.length}`, color:"#a855f7", icon:<Bell size={20}/>, path:"/incidents" },
          { title:"ATTACK CHAINS", value:fChains.length, sub:`Active: ${priorityQueue.length}`, color:"#06b6d4", icon:<Link2 size={20}/>, path:"/attack-chains" },
        ].map((c,i) => (
          <div key={i} onClick={() => c.path && navigate(c.path)}
            style={{background:"rgba(8,18,38,0.95)",border:`1px solid ${c.color}33`,borderRadius:"10px",padding:"14px",display:"flex",justifyContent:"space-between",alignItems:"center",cursor:c.path?"pointer":"default",transition:"border-color 0.2s"}}
          >
            <div>
              <p style={{color:c.color,fontSize:"10px",letterSpacing:"0.5px",margin:0,fontWeight:600}}>{c.title}</p>
              <h2 style={{color:c.color,fontSize:"28px",fontWeight:700,margin:"4px 0"}}>{c.value}</h2>
              <small style={{color:"#64748b",fontSize:"11px"}}>{c.sub}</small>
            </div>
            <div style={{color:c.color,background:`${c.color}18`,width:"40px",height:"40px",borderRadius:"10px",display:"flex",alignItems:"center",justifyContent:"center"}}>{c.icon}</div>
          </div>
        ))}
      </div>

      {/* CHARTS */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1.4fr 1fr",gap:"12px",marginBottom:"12px"}}>

        {/* RISK DISTRIBUTION */}
        <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.12)",borderRadius:"10px",padding:"16px"}}>
          <p style={{color:"#64748b",fontSize:"11px",fontWeight:600,textTransform:"uppercase",letterSpacing:"0.5px",margin:"0 0 12px"}}>Risk Level Distribution</p>
          {riskData.length === 0 ? (
            <p style={{color:"#475569",textAlign:"center",padding:"40px 0",fontSize:"13px"}}>No risk data available</p>
          ) : (
            <div style={{display:"flex",alignItems:"center",gap:"16px"}}>
              <div style={{position:"relative",flex:"0 0 120px",height:"120px"}}>
                <ResponsiveContainer width="100%" height={120}>
                  <PieChart>
                    <Pie data={riskData} dataKey="value" innerRadius={35} outerRadius={55} paddingAngle={2}>
                      {riskData.map((e,i) => <Cell key={i} fill={e.color}/>)}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div style={{position:"absolute",top:"50%",left:"50%",transform:"translate(-50%,-50%)",textAlign:"center"}}>
                  <div style={{fontSize:"18px",fontWeight:700,color:"white"}}>{total||rawLogs.length}</div>
                  <div style={{fontSize:"9px",color:"#64748b"}}>Total</div>
                </div>
              </div>
              <div style={{display:"flex",flexDirection:"column",gap:"6px"}}>
                {riskData.map(d => (
                  <div key={d.name} style={{display:"flex",alignItems:"center",gap:"8px",fontSize:"12px",color:"#94a3b8"}}>
                    <span style={{width:"8px",height:"8px",borderRadius:"2px",background:d.color,flexShrink:0}}/>
                    {d.name} {d.value} {total>0?`(${((d.value/total)*100).toFixed(1)}%)`:""}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* INCIDENT TREND */}
        <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.12)",borderRadius:"10px",padding:"16px"}}>
          <p style={{color:"#64748b",fontSize:"11px",fontWeight:600,textTransform:"uppercase",letterSpacing:"0.5px",margin:"0 0 12px"}}>Incidents Over Time (Last 7 Days)</p>
          <ResponsiveContainer width="100%" height={120}>
            <LineChart data={trendData}>
              <XAxis dataKey="day" stroke="#334155" tick={{fontSize:10,fill:"#475569"}}/>
              <YAxis stroke="#334155" tick={{fontSize:10,fill:"#475569"}} width={25}/>
              <Tooltip contentStyle={{background:"#0f172a",border:"1px solid #1e293b",color:"#e2e8f0",fontSize:"12px"}}/>
              <Line type="monotone" dataKey="count" stroke="#38bdf8" strokeWidth={2} dot={{fill:"#38bdf8",r:3}} label={{position:"top",fill:"#38bdf8",fontSize:10}}/>
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* ATTACK MAP */}
        <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.12)",borderRadius:"10px",padding:"16px"}}>
          <p style={{color:"#64748b",fontSize:"11px",fontWeight:600,textTransform:"uppercase",letterSpacing:"0.5px",margin:"0 0 12px"}}>Top Destination IPs / Attack Map</p>
          <div style={{height:"120px",overflow:"hidden"}}>
            <WorldAttackMap />
          </div>
        </div>
      </div>

      {/* TABLES */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"12px",marginBottom:"12px"}}>

        {/* PRIORITY QUEUE */}
        <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.12)",borderRadius:"10px",padding:"16px"}}>
          <p style={{color:"#64748b",fontSize:"11px",fontWeight:600,textTransform:"uppercase",letterSpacing:"0.5px",margin:"0 0 12px"}}>Priority Queue (Top 10)</p>
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:"12px"}}>
            <thead>
              <tr>{["#","Host","User","Score","Severity","Confidence","Decision"].map(h => (
                <th key={h} style={{color:"#475569",fontWeight:600,padding:"6px 8px",textAlign:"left",borderBottom:"1px solid rgba(255,255,255,0.06)",fontSize:"10px",textTransform:"uppercase"}}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {priorityQueue.length === 0 ? (
                <tr><td colSpan="7" style={{textAlign:"center",padding:"20px",color:"#475569"}}>No data available</td></tr>
              ) : priorityQueue.map((c,i) => (
                <tr key={i} style={{borderBottom:"1px solid rgba(255,255,255,0.04)"}}>
                  <td style={{padding:"8px",color:"#475569"}}>{i+1}</td>
                  <td style={{padding:"8px",color:"#e2e8f0"}}>{c.host}</td>
                  <td style={{padding:"8px",color:"#94a3b8"}}>{c.user}</td>
                  <td style={{padding:"8px",color:c.risk_score>=80?"#ef4444":c.risk_score>=50?"#f97316":"#eab308",fontWeight:700}}>{c.risk_score}</td>
                  <td style={{padding:"8px",color:SEV_COLOR[c.severity]||"#94a3b8",fontWeight:700}}>{c.severity}</td>
                  <td style={{padding:"8px",color:"#94a3b8"}}>{c.confidence}</td>
                  <td style={{padding:"8px",color:c.decision==="ESCALATE"?"#ef4444":c.decision==="INVESTIGATE"?"#f97316":"#eab308",fontWeight:700}}>{c.decision}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* RECENT ATTACK CHAINS */}
        <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.12)",borderRadius:"10px",padding:"16px"}}>
          <p style={{color:"#64748b",fontSize:"11px",fontWeight:600,textTransform:"uppercase",letterSpacing:"0.5px",margin:"0 0 12px"}}>Recent Attack Chains</p>
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:"12px"}}>
            <thead>
              <tr>{["#","Chain Type","Host","User","Risk Score","Severity","Confidence"].map(h => (
                <th key={h} style={{color:"#475569",fontWeight:600,padding:"6px 8px",textAlign:"left",borderBottom:"1px solid rgba(255,255,255,0.06)",fontSize:"10px",textTransform:"uppercase"}}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {recentChains.length === 0 ? (
                <tr><td colSpan="7" style={{textAlign:"center",padding:"20px",color:"#475569"}}>No data available</td></tr>
              ) : recentChains.map((c,i) => (
                <tr key={i} style={{borderBottom:"1px solid rgba(255,255,255,0.04)"}}>
                  <td style={{padding:"8px",color:"#475569"}}>{i+1}</td>
                  <td style={{padding:"8px",color:"#e2e8f0",maxWidth:"160px",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{c.chain_label}</td>
                  <td style={{padding:"8px",color:"#94a3b8"}}>{c.host}</td>
                  <td style={{padding:"8px",color:"#94a3b8"}}>{c.user}</td>
                  <td style={{padding:"8px",color:"#f97316",fontWeight:700}}>{c.risk_score}</td>
                  <td style={{padding:"8px",color:SEV_COLOR[c.severity]||"#94a3b8",fontWeight:700}}>{c.severity}</td>
                  <td style={{padding:"8px",color:"#94a3b8"}}>{c.confidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* RECENT INCIDENTS */}
      <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.12)",borderRadius:"10px",padding:"16px"}}>
        <p style={{color:"#64748b",fontSize:"11px",fontWeight:600,textTransform:"uppercase",letterSpacing:"0.5px",margin:"0 0 12px"}}>Recent Incidents</p>
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:"12px"}}>
          <thead>
            <tr>{["#","Time","Host","User","Chain Type / Module","Event Summary","Severity","Decision","Status"].map(h => (
              <th key={h} style={{color:"#475569",fontWeight:600,padding:"6px 8px",textAlign:"left",borderBottom:"1px solid rgba(255,255,255,0.06)",fontSize:"10px",textTransform:"uppercase"}}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {recentIncidents.length === 0 ? (
              <tr><td colSpan="9" style={{textAlign:"center",padding:"20px",color:"#475569"}}>No incidents</td></tr>
            ) : recentIncidents.map((a,i) => (
              <tr key={i} style={{borderBottom:"1px solid rgba(255,255,255,0.04)"}}>
                <td style={{padding:"8px",color:"#475569"}}>{i+1}</td>
                <td style={{padding:"8px",fontFamily:"monospace",fontSize:"11px",color:"#64748b"}}>{(a.time?.split("T")[0]||"") + " " + (a.time?.split("T")[1]?.split("+")[0]||"")}</td>
                <td style={{padding:"8px",color:"#e2e8f0"}}>{a.host}</td>
                <td style={{padding:"8px",color:"#94a3b8"}}>{a.user}</td>
                <td style={{padding:"8px",color:"#94a3b8"}}>{a.pack||"N/A"}</td>
                <td style={{padding:"8px",color:"#cbd5e1",maxWidth:"220px",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{a.summary||a.title}</td>
                <td style={{padding:"8px",color:SEV_COLOR[a.severity]||"#94a3b8",fontWeight:700}}>{a.severity}</td>
                <td style={{padding:"8px",color:"#f97316",fontWeight:700}}>INVESTIGATE</td>
                <td style={{padding:"8px"}}><span style={{color:"#22c55e",fontSize:"11px",fontWeight:600}}>● OPEN</span></td>
                <td style={{padding:"8px"}}>
                  <button onClick={() => {
                    localStorage.setItem("clearsoc_selected_alert", JSON.stringify(a));
                    navigate("/investigation");
                  }} style={{background:"rgba(56,189,248,0.1)",border:"1px solid rgba(56,189,248,0.3)",color:"#38bdf8",padding:"4px 10px",borderRadius:"6px",cursor:"pointer",fontSize:"11px",fontWeight:600}}>
                    Investigate
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

    </div>
  );
}
