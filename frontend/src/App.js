import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import 'chart.js/auto';
import './App.css';

const API_BASE_URL =
  process.env.REACT_APP_API_BASE_URL ||
  "https://scamshield-api-lzmj.onrender.com";

function App() {
  const [page, setPage] = useState('home');
  const [view, setView] = useState('overview'); // 'overview' | 'analytics'
  const [text, setText] = useState('');
  const [channel, setChannel] = useState('sms');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [audioFile, setAudioFile] = useState(null);
  const [history, setHistory] = useState([]);
  const [expandedId, setExpandedId] = useState(null);
  const [fetchCount, setFetchCount] = useState(0);
  const [expandedCard, setExpandedCard] = useState(null);

  const carouselRef = useRef(null);

  useEffect(() => {
    if (page !== 'home') return;
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.setAttribute('data-revealed', 'true');
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.08, rootMargin: '0px 0px -60px 0px' }
    );
    const timer = setTimeout(() => {
      document.querySelectorAll('.ss .reveal').forEach((el) => observer.observe(el));
    }, 60);
    return () => { clearTimeout(timer); observer.disconnect(); };
  }, [page]);

  useEffect(() => {
    let intervalId;
    const fetchHistory = () => {
      axios.get(`${API_BASE_URL}/api/history/`)
        .then((res) => {
          const freshData = JSON.parse(JSON.stringify(res.data));
          setHistory(freshData);
          setFetchCount(prev => prev + 1);
        })
        .catch((err) => console.error('History fetch error:', err));
    };
    if (page === 'dashboard') {
      fetchHistory();
      intervalId = setInterval(fetchHistory, 3000);
    }
    return () => { if (intervalId) clearInterval(intervalId); };
  }, [page]);

  const scrollCarousel = (direction) => {
    if (carouselRef.current) {
      const scrollAmount = carouselRef.current.offsetWidth * 0.65;
      carouselRef.current.scrollBy({ left: direction === 'left' ? -scrollAmount : scrollAmount, behavior: 'smooth' });
    }
  };

  const triggerPushAlert = (category, score) => {
    if (score >= 30) {
      if (Notification.permission === 'granted') {
        new Notification('ScamShield Alert', { body: 'Threat: ' + category.toUpperCase() });
      } else if (Notification.permission !== 'denied') {
        Notification.requestPermission();
      }
      try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ctx.createOscillator(); const gain = ctx.createGain();
        osc.connect(gain); gain.connect(ctx.destination);
        osc.frequency.value = 800; gain.gain.value = 0.4;
        osc.start(); osc.stop(ctx.currentTime + 0.2);
      } catch (e) { }
    }
  };

  const handleResult = (res, isVoice = false) => {
    if (!res.data || res.data.category === undefined) {
      alert(res.data?.error || "Processing failed. Make sure it's a valid audio file.");
      setLoading(false); setAudioFile(null); return;
    }
    const newData = {
      ...res.data, id: Date.now(), time: new Date().toLocaleTimeString(),
      isVoice: isVoice, sender: isVoice ? 'Manual Voice Upload' : 'Manual Upload'
    };
    setResult(newData);
    setHistory((prev) => [newData, ...prev]);
    setFetchCount(prev => prev + 1);
    triggerPushAlert(res.data.category, res.data.score);
    setLoading(false); setText(''); setAudioFile(null);
    if (document.getElementById("audio-upload")) document.getElementById("audio-upload").value = "";
  };

  const analyzeText = async () => {
    if (!text.trim() || loading) return; setLoading(true);
    try { const res = await axios.post(`${API_BASE_URL}/api/analyze/`, { text, channel }); handleResult(res); }
    catch (err) { alert("Backend Error!"); } setLoading(false);
  };

  const analyzeAudio = async () => {
    if (!audioFile || loading) return; setLoading(true);
    const formData = new FormData(); formData.append('audio', audioFile);
    try { const res = await axios.post(`${API_BASE_URL}/api/voice/`, formData, { headers: { 'Content-Type': 'multipart/form-data' } }); handleResult(res, true); }
    catch (err) { alert("Audio processing failed."); } setLoading(false);
  };

  const totalScans = history.length;
  const threatsBlocked = history.filter((h) => (h.score || 0) >= 30).length;
  const safeMessages = totalScans - threatsBlocked;
  const avgScore = totalScans > 0 ? Math.round(history.reduce((a, b) => a + (b.score || 0), 0) / totalScans) : 0;

  const getColor = (cat) => { if (!cat) return '#94a3b8'; if (cat === 'safe') return '#10b981'; if (cat === 'suspicious') return '#f59e0b'; return '#f43f5e'; };
  const formatTime = (timeStr) => { if (!timeStr) return ''; try { return new Date(timeStr).toLocaleTimeString(); } catch (e) { return timeStr; } };

  const tickColor = '#7c8a88';
  const gridColor = 'rgba(12,31,30,0.06)';

  const lineChartData = {
    labels: history.slice(0, 10).reverse().map((h) => formatTime(h.time)),
    datasets: [{ label: 'Risk Score', data: history.slice(0, 10).reverse().map((h) => h.score || 0), borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.10)', tension: 0.4, fill: true, borderWidth: 2.5, pointBackgroundColor: '#ffffff', pointBorderColor: '#10b981', pointBorderWidth: 2 }],
  };
  const channelCounts = { sms: 0, email: 0, whatsapp: 0, social: 0, voice: 0 };
  history.forEach((h) => { const ch = h.isVoice ? 'voice' : (h.channel || 'unknown'); if (channelCounts[ch] !== undefined) channelCounts[ch]++; });
  const barChartData = {
    labels: Object.keys(channelCounts).map((c) => c.toUpperCase()),
    datasets: [{ label: 'Scans', data: Object.values(channelCounts), backgroundColor: ['#0d9488', '#10b981', '#0ea5e9', '#f59e0b', '#f43f5e'], borderRadius: 8, borderSkipped: false }],
  };
  const categoryCounts = {};
  history.forEach((h) => { if ((h.score || 0) >= 30 && h.category) { const catName = h.category.replace('_', ' ').toUpperCase(); if (catName !== 'SAFE') categoryCounts[catName] = (categoryCounts[catName] || 0) + 1; } });
  const doughnutData = {
    labels: Object.keys(categoryCounts),
    datasets: [{ data: Object.values(categoryCounts), backgroundColor: ['#f43f5e', '#0d9488', '#f59e0b', '#0ea5e9', '#10b981', '#e879f9'], borderWidth: 0, hoverOffset: 8 }],
  };
  const safeVsThreatData = {
    labels: ['Safe', 'Threats'],
    datasets: [{ data: [safeMessages, threatsBlocked], backgroundColor: ['#10b981', '#f43f5e'], borderWidth: 0, hoverOffset: 8 }],
  };

  const statCards = [
    { id: 'accuracy', stat: '99.2%', title: 'Detection Accuracy', color: '#0d9488', desc: 'Industry-leading precision in identifying phishing, OTP theft, and social engineering across all supported channels and languages.' },
    { id: 'speed', stat: '<50ms', title: 'Analysis Speed', color: '#0ea5e9', desc: 'Sub-50ms per-message processing with our optimized NLP pipeline. Real-time protection that never slows your workflow.' },
    { id: 'uptime', stat: '24/7', title: 'Continuous Protection', color: '#10b981', desc: 'Always-on passive interceptor monitors SMS, Email, WhatsApp, and Telegram without any manual intervention.' }
  ];

  const channelList = [
    { key: 'sms', icon: '💬', label: 'SMS' },
    { key: 'email', icon: '✉️', label: 'Email' },
    { key: 'whatsapp', icon: '📱', label: 'WhatsApp' },
    { key: 'social', icon: '🌐', label: 'Social' },
  ];

  /* ============================================================
     LANDING PAGE
     ============================================================ */
  if (page === 'home') {
    const marquee = ['SMS', 'EMAIL', 'WHATSAPP', 'TELEGRAM', 'VOICE CALLS', 'SOCIAL DMs'];
    return (
      <div className="ss">
        <div className="ss-mesh"></div>

        <nav className="ss-nav">
          <div className="ss-nav-pill">
            <div className="ss-logo">
              <span className="ss-logo-mark">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 12 2 2 4-4" /></svg>
              </span>
              ScamShield
            </div>
            <div className="ss-nav-links">
              <a href="#stats">Features</a>
              <a href="#capabilities">Capabilities</a>
              <a href="#how">How it works</a>
            </div>
            <button onClick={() => setPage('dashboard')} className="ss-nav-cta">Launch app</button>
          </div>
        </nav>

        {/* HERO */}
        <header className="ss-hero">
          <div className="ss-hero-left">
            <div className="ss-chip reveal" data-delay="0"><span className="ss-chip-dot"></span> Real-time message protection</div>
            <h1 className="ss-h1">
              <span className="reveal" data-delay="1">Scams die</span><br />
              <span className="ss-h1-grad reveal" data-delay="2">before they land.</span>
            </h1>
            <p className="ss-lead reveal" data-delay="3">
              ScamShield inspects every SMS, email, WhatsApp, Telegram message and voice call the moment it arrives, and flags phishing, OTP theft and social engineering before you ever tap.
            </p>
            <div className="ss-hero-actions reveal" data-delay="4">
              <button onClick={() => setPage('dashboard')} className="ss-btn-glow">
                Open dashboard
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14" /><path d="m12 5 7 7-7 7" /></svg>
              </button>
              <a href="#how" className="ss-btn-line">How it works</a>
            </div>
            <div className="ss-hero-proof reveal" data-delay="4">
              <div><b>99.2%</b><span>accuracy</span></div>
              <div><b>&lt;50ms</b><span>per scan</span></div>
              <div><b>4</b><span>languages</span></div>
            </div>
          </div>

          <div className="ss-hero-right reveal" data-delay="2">
            <div className="ss-card-scan">
              <div className="ss-scan-head">
                <span className="ss-scan-badge">● live scan</span>
                <span className="ss-scan-id">SS-0947</span>
              </div>
              <div className="ss-bubble t1">
                <div className="ss-bubble-meta">Unknown sender · now</div>
                “Dear customer, your account is blocked. Share the OTP now to avoid closure: <b>bit.ly/kyc-upd8</b>”
              </div>
              <div className="ss-checks">
                <div className="ss-check t2"><span className="ss-check-ico bad">✕</span><div>URL reputation<span>1 malicious link found</span></div><b className="bad">fail</b></div>
                <div className="ss-check t3"><span className="ss-check-ico bad">✕</span><div>Urgency language<span>threat + account closure</span></div><b className="bad">fail</b></div>
                <div className="ss-check t4"><span className="ss-check-ico bad">✕</span><div>OTP request<span>credential extraction</span></div><b className="bad">fail</b></div>
              </div>
              <div className="ss-verdict t5">
                <div className="ss-verdict-ring"><span>94</span></div>
                <div className="ss-verdict-info">
                  <b>OTP fraud detected</b>
                  <span>Blocked · alert sent · logged</span>
                </div>
                <span className="ss-verdict-pill">Blocked</span>
              </div>
              <div className="ss-sweepline"></div>
            </div>
            <div className="ss-float ss-float-a">🛡️ Phishing link blocked</div>
            <div className="ss-float ss-float-b">✅ 128 safe messages</div>
          </div>
        </header>

        {/* MARQUEE */}
        <div className="ss-marquee">
          <div className="ss-marquee-track">
            {[...marquee, ...marquee, ...marquee, ...marquee].map((m, i) => (
              <span key={i}>{m}<i>✦</i></span>
            ))}
          </div>
        </div>

        {/* STATS */}
        <section id="stats" className="ss-sec">
          <div className="ss-sec-head reveal">
            <div className="ss-eyebrow">Performance</div>
            <h2>Fast. Accurate. Always on.</h2>
          </div>
          <div className="ss-stats">
            {statCards.map((card, i) => (
              <button
                key={card.id}
                type="button"
                className={`ss-stat reveal ${expandedCard === card.id ? 'open' : ''}`}
                style={{ '--c': card.color }}
                data-delay={i}
                onClick={() => setExpandedCard(expandedCard === card.id ? null : card.id)}
              >
                <div className="ss-stat-num">{card.stat}</div>
                <div className="ss-stat-title">{card.title}</div>
                <div className="ss-stat-desc"><p>{card.desc}</p></div>
                <span className="ss-stat-plus">+</span>
              </button>
            ))}
          </div>
        </section>

        {/* SCAM FAMILIES */}
        <section className="ss-sec">
          <div className="ss-sec-head reveal">
            <div className="ss-eyebrow">Coverage</div>
            <h2>Every scam family, one shield</h2>
          </div>
          <div className="ss-chips">
            {[
              ['🔐', 'OTP Theft', '#f43f5e'], ['🏦', 'Bank Fraud', '#0d9488'], ['🎰', 'Lottery Scam', '#f59e0b'],
              ['💔', 'Romance Scam', '#e879f9'], ['💼', 'Job Scam', '#0ea5e9'], ['📈', 'Investment Scam', '#10b981'],
              ['🎣', 'Phishing', '#8b5cf6'], ['🎭', 'Impersonation', '#f97316'], ['🌍', 'International Scam', '#14b8a6'],
            ].map(([ico, label, c], i) => (
              <div key={label} className="ss-chipcard reveal" data-delay={i % 5} style={{ '--c': c }}>
                <span className="ss-chipcard-ico">{ico}</span>{label}
              </div>
            ))}
          </div>
        </section>

        {/* CAPABILITIES BENTO */}
        <section id="capabilities" className="ss-sec">
          <div className="ss-sec-head reveal">
            <div className="ss-eyebrow">Capabilities</div>
            <h2>Four detectors. One shield.</h2>
          </div>
          <div className="ss-bento">
            <div className="ss-bcard b1 reveal" data-delay="0">
              <div className="ss-bicon">🔗</div>
              <h3>Phishing URL Detection</h3>
              <p>High-speed regex engine flags malicious shortlinks, credential harvester domains, and IDN homograph attacks in under 5ms.</p>
              <div className="ss-url"><s>https://</s><b>hdfc-secure-login.xyz</b><u>/verify</u><span>BLOCKED</span></div>
            </div>
            <div className="ss-bcard b2 reveal" data-delay="1">
              <div className="ss-bicon">🔐</div>
              <h3>OTP and Banking Fraud</h3>
              <p>Detects urgency-driven OTP extraction, UPI payment fraud and fake banking alerts across all languages.</p>
            </div>
            <div className="ss-bcard b3 reveal" data-delay="2">
              <div className="ss-bicon">🎙️</div>
              <h3>Vishing (Voice Phishing)</h3>
              <p>Google Speech API transcribes calls, then NLP flags social engineering cues, impersonation and credential requests.</p>
              <div className="ss-wave">{Array.from({ length: 28 }).map((_, i) => <i key={i} style={{ animationDelay: `${(i % 9) * 0.12}s` }}></i>)}</div>
            </div>
            <div className="ss-bcard b4 reveal" data-delay="3">
              <div className="ss-bicon">🎭</div>
              <h3>Social Engineering</h3>
              <p>Identifies manipulation tactics: fake authority, urgency triggers, emotional pressure and impersonation of trusted contacts.</p>
            </div>
          </div>
        </section>

        {/* BEFORE / AFTER */}
        <section className="ss-sec">
          <div className="ss-sec-head reveal">
            <div className="ss-eyebrow">The difference</div>
            <h2>One tap can cost you everything</h2>
          </div>
          <div className="ss-compare">
            <div className="ss-cmp ss-cmp-bad reveal" data-delay="0">
              <div className="ss-cmp-tag">Without ScamShield</div>
              <div className="ss-msg">Your KYC is expiring today! Click <u>bit.ly/kyc-upd8</u> and share the OTP to keep your account active.</div>
              <ul>
                <li>😰 Looks urgent and official</li>
                <li>👆 You tap the link</li>
                <li>💸 Account drained in minutes</li>
              </ul>
            </div>
            <div className="ss-cmp ss-cmp-good reveal" data-delay="1">
              <div className="ss-cmp-tag">With ScamShield</div>
              <div className="ss-msg ss-msg-blocked">
                <span className="ss-stamp">BLOCKED · 94</span>
                Your KYC is expiring today! Click <u>bit.ly/kyc-upd8</u> and share the OTP to keep your account active.
              </div>
              <ul>
                <li>🛡️ Flagged in under 50ms</li>
                <li>🔔 You get an instant alert</li>
                <li>😌 Nothing lost, nothing clicked</li>
              </ul>
            </div>
          </div>
        </section>

        {/* LANGUAGES */}
        <section className="ss-langs">
          <div className="ss-langs-head reveal">
            <div className="ss-eyebrow">Multi-lingual</div>
            <h2>Built for India's communication landscape</h2>
            <p>Native script detection goes beyond translation, understanding cultural context, regional scam patterns and code-switched text.</p>
          </div>
          <div className="ss-langs-row">
            {['English', 'हिन्दी', 'Hinglish', 'ಕನ್ನಡ'].map((lang, i) => (
              <div key={lang} className="ss-lang reveal" data-delay={i}>{lang}</div>
            ))}
          </div>
        </section>

        {/* HOW */}
        <section id="how" className="ss-sec">
          <div className="ss-sec-head reveal">
            <div className="ss-eyebrow">Pipeline</div>
            <h2>From intercept to protected in three steps</h2>
          </div>
          <div className="ss-steps">
            {[
              { n: '01', t: 'Intercept', d: 'Passive interceptor captures messages from SMS, Email, WhatsApp and Telegram as they arrive.' },
              { n: '02', t: 'Analyze', d: 'Multi-model AI scans for malicious URLs, OTP patterns, urgency language and vishing cues in parallel.' },
              { n: '03', t: 'Protect', d: 'Threats are logged to the dashboard, push alerts fire, and you stay safe without any action.' },
            ].map((s, i) => (
              <div key={s.n} className="ss-step reveal" data-delay={i}>
                <div className="ss-step-n">{s.n}</div>
                <h3>{s.t}</h3>
                <p>{s.d}</p>
              </div>
            ))}
          </div>
        </section>

        {/* CTA */}
        <section className="ss-cta-wrap">
          <div className="ss-cta reveal">
            <h2>Start protecting your messages today</h2>
            <p>No setup, no extensions, no configuration. Just open the dashboard.</p>
            <button onClick={() => setPage('dashboard')} className="ss-btn-glow ss-btn-white">
              Open dashboard
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14" /><path d="m12 5 7 7-7 7" /></svg>
            </button>
          </div>
        </section>

        <footer className="ss-footer">
          <div className="ss-logo">
            <span className="ss-logo-mark">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 12 2 2 4-4" /></svg>
            </span>
            ScamShield
          </div>
          <p>© {new Date().getFullYear()} ScamShield · Built with React and Django</p>
        </footer>
      </div>
    );
  }

  /* ============================================================
     DASHBOARD
     ============================================================ */
  const resScore = result ? (result.score || 0) : 0;
  const resCat = result ? (result.category || 'safe') : 'safe';

  return (
    <div className="ds">
      <div className="ds-mesh"></div>

      <aside className="ds-side">
        <div className="ds-brand">
          <span className="ds-brand-mark">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 12 2 2 4-4" /></svg>
          </span>
          <div>
            <b>ScamShield</b>
            <small>Command Center</small>
          </div>
        </div>

        <div className="ds-side-label">View</div>
        <nav className="ds-nav ds-views">
          <button onClick={() => setView('overview')} className={`ds-nav-btn ${view === 'overview' ? 'active' : ''}`}>
            <span className="ds-nav-ico">🧭</span>
            Overview
            {view === 'overview' && <i className="ds-nav-dot"></i>}
          </button>
          <button onClick={() => setView('analytics')} className={`ds-nav-btn ${view === 'analytics' ? 'active' : ''}`}>
            <span className="ds-nav-ico">📊</span>
            Analytics
            {view === 'analytics' && <i className="ds-nav-dot"></i>}
          </button>
        </nav>

        {view === 'overview' && (
          <>
            <div className="ds-side-label">Scan channel</div>
            <nav className="ds-nav">
              {channelList.map((c) => (
                <button key={c.key} onClick={() => setChannel(c.key)} className={`ds-nav-btn ${channel === c.key ? 'active' : ''}`}>
                  <span className="ds-nav-ico">{c.icon}</span>
                  {c.label}
                  {channel === c.key && <i className="ds-nav-dot"></i>}
                </button>
              ))}
            </nav>
          </>
        )}

        <div className="ds-side-foot">
          <div className="ds-live"><span className="ds-live-dot"></span> Live · syncing every 3s</div>
          <button onClick={() => setPage('home')} className="ds-home-btn">← Back to home</button>
        </div>
      </aside>

      <main className="ds-main">
        <div className="ds-title">
          <div>
            <h1>{view === 'overview' ? 'Threat Overview' : 'Analytics'}</h1>
            {view === 'overview'
              ? <p>Scanning on <b>{channel.toUpperCase()}</b> · paste a message or upload a voice note</p>
              : <p>Live charts across all scanned messages · <b>{totalScans} scans</b></p>}
          </div>
          <div className="ds-title-date">
            <span className="ds-title-badge">● operational</span>
            <span>{new Date().toLocaleDateString()}</span>
          </div>
        </div>

        {/* ================= OVERVIEW ================= */}
        {view === 'overview' && (
          <>
            {/* Scan bar */}
            <div className="ds-scan">
              <div className="ds-scan-ico">🔍</div>
              <input type="text" value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste a suspicious message to scan..." className="ds-input" onKeyDown={(e) => e.key === 'Enter' && analyzeText()} />
              <input type="file" accept=".wav, .ogg, .mp3, .m4a" onChange={(e) => setAudioFile(e.target.files[0])} id="audio-upload" hidden />
              <label htmlFor="audio-upload" className={`ds-mic ${audioFile ? 'has-file' : ''}`} title={audioFile ? audioFile.name : 'Upload voice file'}>🎙️</label>
              {audioFile && <button onClick={analyzeAudio} disabled={loading} className="ds-btn-ghost">Analyze Voice</button>}
              <button onClick={analyzeText} disabled={loading || !text.trim()} className="ds-btn-scan">
                {loading ? '⏳ Scanning...' : 'Scan now'}
              </button>
            </div>

            {/* Latest result */}
            {result && (
              <div className={`ds-result ${resScore >= 30 ? 'threat' : 'safe'}`} style={{ '--rc': getColor(resCat), '--pct': `${Math.min(resScore, 100) * 3.6}deg` }}>
                <div className="ds-ring"><div><span>{resScore}</span><small>risk</small></div></div>
                <div className="ds-result-body">
                  <div className="ds-result-eyebrow">Latest scan</div>
                  <div className="ds-result-cat" style={{ color: getColor(resCat) }}>
                    {resScore >= 30 ? '⚠️' : '✅'} {resCat.replace('_', ' ').toUpperCase()}
                  </div>
                  <div className="ds-tags">
                    {(result.triggers || []).length > 0
                      ? result.triggers.map((t, i) => (<span key={i} className={`ds-tag ${(t || '').toLowerCase().includes('safe') ? 'ok' : 'bad'}`}>{t}</span>))
                      : <span className="ds-tag ok">No triggers</span>}
                  </div>
                </div>
                <button className="ds-result-x" onClick={() => setResult(null)} aria-label="Dismiss">✕</button>
              </div>
            )}

            {/* KPIs */}
            <div key={fetchCount} className="ds-kpis">
              <div className="ds-kpi k-total"><span className="ds-kpi-ico">📡</span><span className="ds-kpi-label">Total scans</span><span className="ds-kpi-val">{totalScans}</span><i></i></div>
              <div className="ds-kpi k-danger"><span className="ds-kpi-ico">🚨</span><span className="ds-kpi-label">Threats blocked</span><span className="ds-kpi-val">{threatsBlocked}</span><i></i></div>
              <div className="ds-kpi k-safe"><span className="ds-kpi-ico">✅</span><span className="ds-kpi-label">Safe messages</span><span className="ds-kpi-val">{safeMessages}</span><i></i></div>
              <div className="ds-kpi k-avg"><span className="ds-kpi-ico">⚡</span><span className="ds-kpi-label">Avg risk score</span><span className="ds-kpi-val">{avgScore}</span><i></i></div>
            </div>

            {/* Grid */}
            <div className="ds-grid">
              <section className="ds-card ds-feed">
                <div className="ds-card-head">Live security feed <span className="ds-card-meta">updates every 3s</span></div>
                <div className="ds-feed-list">
                  {history.length === 0 ? (
                    <div className="ds-empty"><div>📡</div>Waiting for intercepts...</div>
                  ) : (
                    history.map((h) => {
                      const hCat = h.category || 'safe';
                      const hChan = h.isVoice ? 'VOICE' : (h.channel || 'manual');
                      const hTriggers = h.triggers || [];
                      const hText = h.text === '[VOICE CALL]' ? '🎙️ Voice transcription analyzed' : (h.text || 'No text data');
                      const hTime = formatTime(h.time);
                      const hScore = h.score || 0;
                      const isExpanded = expandedId === h.id;
                      const senderStr = (h.sender || '').toLowerCase();
                      const isAutoIntercepted = senderStr !== '' && !senderStr.includes('manual') && senderStr !== 'unknown';

                      return (
                        <div key={h.id} onClick={() => setExpandedId(isExpanded ? null : h.id)} className={`ds-row ${hScore >= 30 ? 'threat' : 'safe'} ${isExpanded ? 'open' : ''}`} style={{ '--rc': getColor(hCat) }}>
                          <div className="ds-row-top">
                            <div className="ds-row-left">
                              <span className="ds-row-dot"></span>
                              <div>
                                <div className="ds-row-cat" style={{ color: getColor(hCat) }}>{hCat.replace('_', ' ').toUpperCase()}</div>
                                {isAutoIntercepted && <div className="ds-row-sender">From: {h.sender}</div>}
                              </div>
                            </div>
                            <div className="ds-row-right">
                              <span className="ds-score" style={{ color: getColor(hCat) }}>{hScore}</span>
                              {isAutoIntercepted && <span className="ds-auto">AUTO</span>}
                              <span className="ds-time">{hTime}</span>
                              <span className="ds-chan">{hChan}</span>
                            </div>
                          </div>
                          <div className="ds-row-text">{hText}</div>
                          <div className="ds-bar"><div style={{ width: `${Math.min(hScore, 100)}%` }}></div></div>

                          {isExpanded && (
                            <div className="ds-expand">
                              <div className="ds-expand-text">{hText}</div>
                              {h.transcript && <div className="ds-transcript">🎤 {h.transcript}</div>}
                              <div className="ds-expand-meta">
                                <div>Channel: <strong>{hChan}</strong></div>
                                <div>Language: <strong>{(h.language || 'english').toUpperCase()}</strong></div>
                              </div>
                              <div className="ds-expand-trig">
                                <strong>Triggers:</strong>
                                <div className="ds-tags">
                                  {hTriggers.length > 0 ? hTriggers.map((t, i) => (<span key={i} className={`ds-tag ${(t || '').toLowerCase().includes('safe') ? 'ok' : 'bad'}`}>{t}</span>)) : <span className="ds-tag ok">None</span>}
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </section>

              <section className="ds-card ds-c1">
                <div className="ds-card-head">Threat types</div>
                <div className="ds-chart">
                  {Object.keys(categoryCounts).length > 0 ? (
                    <Doughnut data={doughnutData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { boxWidth: 8, font: { size: 10 }, padding: 10, color: tickColor } } }, cutout: '72%' }} />
                  ) : <div className="ds-empty"><div>🛡️</div>No threats</div>}
                </div>
              </section>

              <section className="ds-card ds-c2">
                <div className="ds-card-head">Scan origins</div>
                <div className="ds-chart">
                  <Bar data={barChartData} options={{ responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { stepSize: 1, color: tickColor }, grid: { color: gridColor } }, x: { ticks: { color: tickColor }, grid: { display: false } } }, plugins: { legend: { display: false } } }} />
                </div>
              </section>

              <section className="ds-card ds-c3">
                <div className="ds-card-head">Risk trend · last 10 scans</div>
                <div className="ds-chart">
                  <Line data={lineChartData} options={{ responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, max: 100, ticks: { color: tickColor }, grid: { color: gridColor } }, x: { ticks: { color: tickColor }, grid: { display: false } } }, plugins: { legend: { display: false } }, elements: { point: { radius: 4, hoverRadius: 6 } } }} />
                </div>
              </section>
            </div>
          </>
        )}

        {/* ================= ANALYTICS (graphs only) ================= */}
        {view === 'analytics' && (
          <div className="ds-an">
            <section className="ds-card ds-an-card ds-an-wide">
              <div className="ds-card-head">Risk trend · last 10 scans <span className="ds-card-meta">updates every 3s</span></div>
              <div className="ds-chart ds-chart-xl">
                {totalScans > 0 ? (
                  <Line data={lineChartData} options={{ responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, max: 100, title: { display: true, text: 'Risk score', color: tickColor }, ticks: { color: tickColor, font: { size: 13 } }, grid: { color: gridColor } }, x: { ticks: { color: tickColor, font: { size: 12 } }, grid: { display: false } } }, plugins: { legend: { display: false } }, elements: { point: { radius: 5, hoverRadius: 8 } } }} />
                ) : <div className="ds-empty"><div>📡</div>No scans yet</div>}
              </div>
            </section>

            <section className="ds-card ds-an-card">
              <div className="ds-card-head">Scan origins</div>
              <div className="ds-chart ds-chart-lg">
                <Bar data={barChartData} options={{ responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { stepSize: 1, color: tickColor, font: { size: 13 } }, grid: { color: gridColor } }, x: { ticks: { color: tickColor, font: { size: 13 } }, grid: { display: false } } }, plugins: { legend: { display: false } } }} />
              </div>
            </section>

            <section className="ds-card ds-an-card">
              <div className="ds-card-head">Threat types</div>
              <div className="ds-chart ds-chart-lg">
                {Object.keys(categoryCounts).length > 0 ? (
                  <Doughnut data={doughnutData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { boxWidth: 12, font: { size: 13 }, padding: 14, color: tickColor } } }, cutout: '65%' }} />
                ) : <div className="ds-empty"><div>🛡️</div>No threats</div>}
              </div>
            </section>

            <section className="ds-card ds-an-card ds-an-wide">
              <div className="ds-card-head">Safe vs threat</div>
              <div className="ds-chart ds-chart-lg">
                {totalScans > 0 ? (
                  <Doughnut data={safeVsThreatData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { boxWidth: 12, font: { size: 13 }, padding: 14, color: tickColor } } }, cutout: '65%' }} />
                ) : <div className="ds-empty"><div>📡</div>No scans yet</div>}
              </div>
            </section>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
