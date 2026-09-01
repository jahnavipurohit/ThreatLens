import { useState } from "react";
import { AlertTriangle, CheckCircle2, FileSearch, Fingerprint, Mail, MapPin, ShieldCheck, Upload } from "lucide-react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000/api";

function Meter({ label, value, tone = "danger" }) {
  return <div className="meter"><div className="meter-label"><span>{label}</span><strong>{value}/100</strong></div><div className="track"><span className={tone} style={{ width: `${value}%` }} /></div></div>;
}

function App() {
  const [file, setFile] = useState();
  const [data, setData] = useState();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const submit = async () => {
    if (!file) return;
    setLoading(true); setError("");
    const body = new FormData(); body.append("file", file);
    try {
      const response = await fetch(`${API}/analyze-email`, { method: "POST", body });
      const json = await response.json();
      if (!response.ok) throw new Error(json.error || "Analysis failed");
      setData(json);
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  };
  const result = data?.result;
  return <main>
    <header><div className="brand"><ShieldCheck size={28}/><div><strong>ThreatLens</strong><span>Email forensic intelligence</span></div></div><span className="prototype">HACKATHON PROTOTYPE</span></header>
    <section className="hero"><div><span className="eyebrow">FORENSIC EMAIL ANALYSIS</span><h1>Turn suspicious email into<br/><em>explainable evidence.</em></h1><p>Inspect identity, authentication, infrastructure, and intent—without executing message content.</p></div>
      <div className="upload-card"><Upload/><h2>Analyze an email</h2><p>Upload a raw RFC email file. Maximum 10 MB.</p><label className="drop"><input type="file" accept=".eml,message/rfc822" onChange={e => setFile(e.target.files[0])}/><Mail/><span>{file ? file.name : "Choose .eml file"}</span></label><button onClick={submit} disabled={!file || loading}>{loading ? "Analyzing…" : "Start forensic analysis"}</button>{error && <div className="error">{error}</div>}</div>
    </section>
    {!data && <section className="capabilities"><div><Fingerprint/><h3>Identity checks</h3><p>Compare From, Reply-To, Return-Path and signing domains.</p></div><div><FileSearch/><h3>IOC extraction</h3><p>Surface URLs, domains, IP addresses, and attachment metadata.</p></div><div><MapPin/><h3>Origin evidence</h3><p>Reconstruct observable infrastructure with explicit caveats.</p></div></section>}
    {data && <section className="results">
      <div className="result-heading"><div><span className="eyebrow">ANALYSIS COMPLETE</span><h2>{result.metadata.subject || "(No subject)"}</h2><p>{result.metadata.from}</p></div><div className={`verdict ${data.verdict.toLowerCase()}`}><AlertTriangle/> {data.verdict}</div></div>
      <div className="grid summary"><article><h3>Risk assessment</h3><Meter label="Threat risk" value={data.threat_score}/><Meter label="Fraud confidence" value={Math.round(result.assessment.fraud_confidence * 100)}/><Meter label="Origin confidence" value={data.origin_confidence} tone="info"/><p className="caveat">{result.assessment.confidence_method}</p><p className="caveat">{result.caveat}</p></article><article><h3>Authentication</h3>{Object.entries(result.assessment.authentication).map(([name,status]) => <div className="auth" key={name}><span>{status === "pass" ? <CheckCircle2/> : <AlertTriangle/>}{name.toUpperCase()}</span><b className={status}>{status}</b></div>)}</article></div>
      <div className="grid"><article><h3>Explainable evidence</h3>{result.assessment.evidence.length ? result.assessment.evidence.map((e,i)=><div className="evidence" key={i}><span>+{e.weight}</span><div><b>{e.description}</b><small>{e.category}</small></div></div>) : <p>No high-risk rule matches were found.</p>}</article><article><h3>Model analysis</h3><div className="ioc"><b>Existing model</b><span>{Math.round(result.assessment.model.phishing_probability * 100)}%</span></div><div className="ioc"><b>RoBERTa</b><span>{result.assessment.huggingface_model.available ? `${Math.round(result.assessment.huggingface_model.fraud_probability * 100)}%` : "Unavailable"}</span></div><h3 style={{marginTop: 28}}>Indicators</h3>{["urls","domains","emails"].map(type=><div className="ioc" key={type}><b>{type}</b><span>{result.indicators[type].length}</span></div>)}<div className="ioc"><b>IP addresses</b><span>{result.indicators.ips.length}</span></div><div className="ioc"><b>Relay hops</b><span>{result.received.length}</span></div></article></div>
      <a className="report" href={`${API}/analysis/${data.analysis_id}/report`}>Download forensic report</a>
    </section>}
  </main>;
}
export default App;
