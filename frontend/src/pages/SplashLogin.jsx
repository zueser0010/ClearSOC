import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

export default function SplashLogin() {
  const navigate = useNavigate();
  const [bootStep, setBootStep] = useState(0);
  const [ready, setReady] = useState(false);

  const refGrid      = useRef(null);
  const refMatrix    = useRef(null);
  const refParticles = useRef(null);
  const refHex       = useRef(null);
  const rafIds       = useRef([]);

  const BOOT_STEPS = [
    "LOADING MODULES",
    "CONNECTING WAZUH",
    "BUILDING RULESET",
    "MAPPING ATT&CK",
    "SYSTEM READY",
  ];

  function resize(canvas) {
    const w = canvas.parentElement.offsetWidth;
    const h = canvas.parentElement.offsetHeight;
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width  = w;
      canvas.height = h;
    }
    return { w, h };
  }

  function startGrid(canvas) {
    const ctx = canvas.getContext("2d");
    let t = 0;
    function frame() {
      const { w, h } = resize(canvas);
      ctx.clearRect(0, 0, w, h);
      const vx = w / 2, vy = h * 0.52;
      const cols = 24, rows = 18, spread = 2.2;
      const speed = 0.4;
      ctx.lineWidth = 0.5;
      ctx.strokeStyle = "rgba(15,100,120,0.55)";
      for (let i = -cols; i <= cols; i++) {
        const ox = i * (w / cols);
        ctx.beginPath();
        ctx.moveTo(vx + ox * 0.01, vy);
        ctx.lineTo(vx + ox * spread, h + 20);
        ctx.stroke();
      }
      const rowOff = (t * speed) % ((h - vy) / rows);
      for (let j = 0; j <= rows; j++) {
        const pct = j / rows;
        const y   = vy + pct * (h - vy) + rowOff * (1 - pct * 0.5);
        if (y > h) continue;
        const xScale = ((y - vy) / (h - vy)) * spread;
        ctx.strokeStyle = `rgba(15,100,120,${(pct * 0.7 + 0.05) * 0.6})`;
        ctx.lineWidth   = 0.4 + pct * 0.5;
        ctx.beginPath();
        ctx.moveTo(vx - w * xScale, y);
        ctx.lineTo(vx + w * xScale, y);
        ctx.stroke();
      }
      ctx.strokeStyle = "rgba(15,180,180,0.18)";
      ctx.lineWidth   = 1.2;
      ctx.beginPath(); ctx.moveTo(0, vy); ctx.lineTo(w, vy); ctx.stroke();
      t++;
      rafIds.current.push(requestAnimationFrame(frame));
    }
    rafIds.current.push(requestAnimationFrame(frame));
  }

  function startMatrix(canvas) {
    const ctx  = canvas.getContext("2d");
    const { w, h } = resize(canvas);
    const colW = 14;
    const cols  = Math.floor(w / colW);
    const drops = Array.from({ length: cols }, () => Math.random() * -50);
    const chars = "01アイウエカサタナパラ0110CLEARSOCSIEM";
    function frame() {
      ctx.fillStyle = "rgba(2,10,18,0.18)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      for (let i = 0; i < drops.length; i++) {
        const ch     = chars[Math.floor(Math.random() * chars.length)];
        const bright = Math.random() > 0.93;
        ctx.fillStyle = bright
          ? "rgba(200,255,255,0.9)"
          : "rgba(15,140,140,0.6)";
        ctx.font = `${bright ? "bold " : ""}10px monospace`;
        ctx.fillText(ch, i * colW, drops[i] * colW);
        if (drops[i] * colW > canvas.height && Math.random() > 0.97) drops[i] = 0;
        drops[i] += 0.5 + Math.random() * 0.3;
      }
      rafIds.current.push(requestAnimationFrame(frame));
    }
    rafIds.current.push(requestAnimationFrame(frame));
  }

  function startParticles(canvas) {
    const ctx = canvas.getContext("2d");
    const { w, h } = resize(canvas);
    const pts = Array.from({ length: 70 }, () => ({
      x:  Math.random() * w,
      y:  Math.random() * h,
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
      r:  Math.random() * 1.8 + 0.5,
      d:  Math.random(),
    }));
    function frame() {
      const cw = canvas.width, ch = canvas.height;
      ctx.clearRect(0, 0, cw, ch);
      pts.forEach((p) => {
        p.x += p.vx * (0.5 + p.d * 0.8);
        p.y += p.vy * (0.5 + p.d * 0.8);
        if (p.x < 0 || p.x > cw) p.vx *= -1;
        if (p.y < 0 || p.y > ch) p.vy *= -1;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(15,${150 + Math.floor(p.d * 80)},${150 + Math.floor(p.d * 80)},${0.2 + p.d * 0.5})`;
        ctx.fill();
      });
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(pts[i].x, pts[i].y);
            ctx.lineTo(pts[j].x, pts[j].y);
            ctx.strokeStyle = `rgba(15,160,160,${(1 - dist / 120) * 0.18})`;
            ctx.lineWidth   = 0.5;
            ctx.stroke();
          }
        }
      }
      rafIds.current.push(requestAnimationFrame(frame));
    }
    rafIds.current.push(requestAnimationFrame(frame));
  }

  function startHexBg(canvas) {
    const ctx = canvas.getContext("2d");
    const { w, h } = resize(canvas);
    const hexes = Array.from({ length: 22 }, () => ({
      x:     Math.random() * w,
      y:     Math.random() * h,
      r:     20 + Math.random() * 45,
      vx:    (Math.random() - 0.5) * 0.18,
      vy:    (Math.random() - 0.5) * 0.18,
      phase: Math.random() * Math.PI * 2,
    }));
    let t = 0;
    function hexPath(cx, cy, r) {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const a = Math.PI / 6 + (i * Math.PI) / 3;
        i === 0
          ? ctx.moveTo(cx + r * Math.cos(a), cy + r * Math.sin(a))
          : ctx.lineTo(cx + r * Math.cos(a), cy + r * Math.sin(a));
      }
      ctx.closePath();
    }
    function frame() {
      const cw = canvas.width, ch = canvas.height;
      ctx.clearRect(0, 0, cw, ch);
      t += 0.01;
      hexes.forEach((hx) => {
        hx.x += hx.vx; hx.y += hx.vy;
        if (hx.x < -60) hx.x = cw + 60;
        if (hx.x > cw + 60) hx.x = -60;
        if (hx.y < -60) hx.y = ch + 60;
        if (hx.y > ch + 60) hx.y = -60;
        const pulse = 0.5 + 0.5 * Math.sin(t * 1.2 + hx.phase);
        hexPath(hx.x, hx.y, hx.r);
        ctx.strokeStyle = `rgba(15,140,140,${0.25 * pulse})`;
        ctx.lineWidth   = 0.6;
        ctx.stroke();
      });
      rafIds.current.push(requestAnimationFrame(frame));
    }
    rafIds.current.push(requestAnimationFrame(frame));
  }

  useEffect(() => {
    if (bootStep < BOOT_STEPS.length) {
      const t = setTimeout(
        () => setBootStep((s) => s + 1),
        bootStep === 0 ? 1000 : 480
      );
      return () => clearTimeout(t);
    } else {
      const t = setTimeout(() => setReady(true), 400);
      return () => clearTimeout(t);
    }
  }, [bootStep]);

  useEffect(() => {
    if (refGrid.current)      startGrid(refGrid.current);
    if (refMatrix.current)    startMatrix(refMatrix.current);
    if (refParticles.current) startParticles(refParticles.current);
    if (refHex.current)       startHexBg(refHex.current);
    return () => rafIds.current.forEach(cancelAnimationFrame);
  }, []);

  const bootPct = Math.round((bootStep / BOOT_STEPS.length) * 100);

  return (
    <div className="splash-root">
      <canvas ref={refGrid}      className="splash-canvas splash-grid"      />
      <canvas ref={refMatrix}    className="splash-canvas splash-matrix"    />
      <canvas ref={refHex}       className="splash-canvas splash-hexbg"     />
      <canvas ref={refParticles} className="splash-canvas splash-particles" />
      <div className="splash-scan1" />
      <div className="splash-scan2" />
      <div className="splash-vignette" />

      <div className="splash-center">
        <svg className="splash-logo" viewBox="0 0 400 300" xmlns="http://www.w3.org/2000/svg">
          <circle className="pulse-ring pr1" cx="200" cy="150" r="118" fill="none" stroke="#0FBFBF" strokeWidth="1.2"/>
          <circle className="pulse-ring pr2" cx="200" cy="150" r="118" fill="none" stroke="#0FBFBF" strokeWidth="1.2"/>
          <circle className="ring-draw" cx="200" cy="150" r="118" fill="none" stroke="#1A3A52" strokeWidth="0.6"/>
          <circle className="ring-draw" style={{animationDelay:".15s"}} cx="200" cy="150" r="123" fill="none" stroke="#0FBFBF" strokeWidth="0.8"/>
          <g stroke="#0FBFBF" strokeWidth="0.6" className="ticks-group">
            <line x1="200" y1="32"  x2="200" y2="22"/>
            <line x1="200" y1="268" x2="200" y2="278"/>
            <line x1="318" y1="150" x2="328" y2="150"/>
            <line x1="82"  y1="150" x2="72"  y2="150"/>
          </g>
          <polygon className="hex-outer" points="200,42 292.2,96 292.2,204 200,258 107.8,204 107.8,96"
            fill="#060F18" stroke="#1C4A6A" strokeWidth="1.5"/>
          <polygon className="hex-inner" points="200,62 274.9,106 274.9,194 200,238 125.1,194 125.1,106"
            fill="#090E1A" stroke="#1E5578" strokeWidth="0.8"/>
          <g className="radar-sweep">
            <path d="M200,150 L200,72 A78,78 0 0,1 239,85.5 Z" fill="#0A7070" opacity="0.22"/>
            <line x1="200" y1="150" x2="200" y2="72" stroke="#0FBFBF" strokeWidth="0.7" opacity="0.7"/>
          </g>
          <circle className="radar-circle" style={{animationDelay:"1.2s"}} cx="200" cy="150" r="28" fill="none" stroke="#0F9090" strokeWidth="0.8"/>
          <circle className="radar-circle" style={{animationDelay:"1.35s"}} cx="200" cy="150" r="52" fill="none" stroke="#0F9090" strokeWidth="0.6"/>
          <circle className="radar-circle" style={{animationDelay:"1.5s"}} cx="200" cy="150" r="78" fill="none" stroke="#0F9090" strokeWidth="0.5"/>
          <path className="eye-shape" d="M148,150 Q200,110 252,150 Q200,190 148,150 Z"
            fill="rgba(15,144,144,0.07)" stroke="#0FBFBF" strokeWidth="1.2" style={{animationDelay:"1.6s"}}/>
          <circle className="iris-ring" cx="200" cy="150" r="18" fill="none" stroke="#0FBFBF" strokeWidth="0.5"/>
          <circle className="iris-ring" style={{animationDelay:".1s"}} cx="200" cy="150" r="24" fill="none" stroke="#0FBFBF" strokeWidth="0.4"/>
          <circle className="pupil-pop" cx="200" cy="150" r="12" fill="#0FBFBF" style={{animationDelay:"1.9s"}}/>
          <circle className="pupil-pop" cx="200" cy="150" r="5"  fill="#040C16" style={{animationDelay:"2.0s"}}/>
          <circle className="pupil-pop" cx="200" cy="150" r="2"  fill="#0FBFBF" style={{animationDelay:"2.1s"}}/>
          <polyline className="circuit" points="107.8,150 92,150 92,128 68,128" fill="none" stroke="#1A4A6A" strokeWidth="0.8" style={{animationDelay:"2.1s"}}/>
          <polyline className="circuit" points="292.2,150 308,150 308,128 332,128" fill="none" stroke="#1A4A6A" strokeWidth="0.8" style={{animationDelay:"2.15s"}}/>
          <polyline className="circuit" points="130,213 115,213 115,232 92,232" fill="none" stroke="#1A4A6A" strokeWidth="0.8" style={{animationDelay:"2.2s"}}/>
          <polyline className="circuit" points="270,213 285,213 285,232 308,232" fill="none" stroke="#1A4A6A" strokeWidth="0.8" style={{animationDelay:"2.2s"}}/>
          <circle className="cdot" cx="68"  cy="128" r="2.5" fill="#0FBFBF" style={{animationDelay:"2.35s"}}/>
          <circle className="cdot" cx="332" cy="128" r="2.5" fill="#0FBFBF" style={{animationDelay:"2.35s"}}/>
          <circle className="cdot" cx="92"  cy="232" r="2.5" fill="#0FBFBF" style={{animationDelay:"2.4s"}}/>
          <circle className="cdot" cx="308" cy="232" r="2.5" fill="#0FBFBF" style={{animationDelay:"2.4s"}}/>
        </svg>

        <h1 className="splash-title">ClearSOC</h1>
        <div className="splash-accent-bars">
          <span /><span /><span />
        </div>
        <h3 className="splash-sub">SOC PLATFORM</h3>
        <p className="splash-tag">DETECT · CORRELATE · INVESTIGATE</p>

        {!ready ? (
          <div className="boot-box">
            <div className="boot-dots">
              <span /><span /><span />
            </div>
            <span className="boot-label">
              {bootStep < BOOT_STEPS.length ? BOOT_STEPS[bootStep] : "SYSTEM READY"}
            </span>
            <div className="boot-bar">
              <div className="boot-fill" style={{ width: `${bootPct}%` }} />
            </div>
          </div>
        ) : (
          <div className="login-box">
            <div className="login-field">
              <span className="login-icon">⬡</span>
              <input
                type="text"
                placeholder="Username"
                defaultValue="admin"
                autoComplete="username"
              />
            </div>
            <div className="login-field">
              <span className="login-icon">◈</span>
              <input
                type="password"
                placeholder="Password"
                defaultValue="clearsoc"
                autoComplete="current-password"
              />
            </div>
            <button className="login-btn" onClick={() => navigate("/dashboard")}>
              <span>ENTER CLEARSOC</span>
              <span className="btn-arrow">→</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
