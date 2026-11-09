import { useEffect, useMemo, useState } from 'react';
import { Shield, LayoutDashboard, ScanSearch, SlidersHorizontal, Bot, ClipboardList, Languages, Activity, AlertTriangle, CheckCircle2, Ban, Eye, Clock3, Menu, LockKeyhole } from 'lucide-react';
import { messages, type Lang, type Key } from './i18n';

type Finding = { type:string; severity:string; masked:string };
type ScanResult = { decision:'ALLOW'|'BLOCK'|'REDACT'|'REVIEW'; findings:Finding[]; safeText?:string; policy:string };
type Audit = { id:number; event:string; outcome:string; rule:string; created_at:string };
type Page = 'dashboard'|'scanner'|'policies'|'gate'|'audit';
const navIcons = { dashboard:LayoutDashboard, scanner:ScanSearch, policies:SlidersHorizontal, gate:Bot, audit:ClipboardList };
const labels: Record<Page,Key> = { dashboard:'dashboard', scanner:'scanner', policies:'policies', gate:'agentGate', audit:'audit' };
const decisionClass = (d:string) => d.toLowerCase();
export default function App() {
  const [lang,setLang] = useState<Lang>(() => (localStorage.getItem('ag-lang') as Lang) || 'en');
  const [page,setPage] = useState<Page>('dashboard');
  const [api,setApi] = useState(false);
  const [textValue,setTextValue] = useState('');
  const [scan,setScan] = useState<ScanResult|null>(null);
  const [agent,setAgent] = useState('Support Agent');
  const [action,setAction] = useState('read_report');
  const [resource,setResource] = useState('reports/monthly');
  const [gate,setGate] = useState<any>(null);
  const [audit,setAudit] = useState<Audit[]>([]);
  const [busy,setBusy] = useState(false);
  const t = (k:Key) => messages[lang][k] || messages.en[k];
  const rtl = lang === 'ar';
  useEffect(()=>{ localStorage.setItem('ag-lang',lang); document.documentElement.dir=rtl?'rtl':'ltr'; document.documentElement.lang=lang; },[lang,rtl]);
  async function refresh() { try { const r=await fetch('/api/health'); setApi(r.ok); const a=await fetch('/api/audit'); if(a.ok) setAudit(await a.json()); } catch { setApi(false); } }
  useEffect(()=>{ refresh(); },[]);
  const stats = useMemo(()=>({scans:audit.filter(x=>x.event==='DATA_SCAN').length,blocked:audit.filter(x=>x.outcome==='BLOCK').length,findings:audit.filter(x=>x.event==='DATA_SCAN'&&x.outcome!=='ALLOW').length}),[audit]);
  async function runScan(value=textValue) { setBusy(true); try { const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:value})}); const data=await r.json(); setScan(data); await refresh(); } catch { setScan(null); } finally { setBusy(false); } }
  async function authorize() { setBusy(true); try { const r=await fetch('/api/authorize-action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({agent,action,resource})}); setGate(await r.json()); await refresh(); } catch { setGate({allowed:false,reason:'API unavailable'}); } finally { setBusy(false); } }
  const nav:Page[]=['dashboard','scanner','policies','gate','audit'];
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Shield size={23}/></div><div><b>ActionGuard<span> AI</span></b><small>{t('navBrand')}</small></div></div>
      <div className="nav-label">WORKSPACE</div>
      {nav.map(item=>{const Icon=navIcons[item];return <button key={item} className={`nav-item ${page===item?'active':''}`} onClick={()=>setPage(item)}><Icon size={18}/><span>{t(labels[item])}</span>{page===item&&<i/>}</button>})}
      <div className="sidebar-bottom"><div className="status-dot"/><div><b>{t('online')}</b><small>{api?t('connected'):t('unavailable')}</small></div></div>
    </aside>
    <main className="main">
      <header className="topbar"><div><div className="eyebrow">ACTIONGUARD / SECURITY CENTER</div><h1>{t(page==='dashboard'?'overview':labels[page])}</h1></div><div className="top-actions"><span className="env-pill"><span/> {t('demo')}</span><div className="lang-select"><Languages size={16}/><select value={lang} onChange={e=>setLang(e.target.value as Lang)} aria-label={t('language')}><option value="en">English</option><option value="ar">العربية</option><option value="zh-CN">简体中文</option></select></div></div></header>
      <div className="content">
        {page==='dashboard'&&<><p className="subtitle">{t('subtitle')}</p><div className="notice"><AlertTriangle size={18}/><div><b>{t('demo')}</b><p>{t('demoNote')}</p></div></div>
          <div className="stat-grid"><Stat icon={<ScanSearch/>} label={t('scans')} value={stats.scans} tone="blue"/><Stat icon={<Ban/>} label={t('blocked')} value={stats.blocked} tone="red"/><Stat icon={<AlertTriangle/>} label={t('findings')} value={stats.findings} tone="amber"/><Stat icon={<Shield/>} label={t('agents')} value="1" tone="green"/></div>
          <div className="panel-grid"><section className="panel"><PanelTitle title={t('recent')} icon={<Activity/>}/>{audit.slice(0,5).length?audit.slice(0,5).map(x=><AuditRow key={x.id} item={x}/>):<div className="empty">{t('clean')}</div>}<button className="text-button" onClick={()=>setPage('audit')}>{t('viewAll')} →</button></section><section className="panel quick-panel"><PanelTitle title="Quick security tests" icon={<LockKeyhole/>}/><p className="muted">Run safe synthetic checks to verify the backend.</p><button className="quick-action" onClick={()=>{setPage('scanner');setTextValue('Hello, this is a normal business message.')}}><CheckCircle2/> {t('scanSafe')}</button><button className="quick-action" onClick={()=>{setPage('scanner');setTextValue('api_key=FAKE_DEMO_KEY_1234567890')}}><AlertTriangle/> {t('scanSecret')}</button><button className="quick-action" onClick={()=>{setPage('gate');setAction('delete_customer_records')}}><Ban/> {t('gateDanger')}</button></section></div>
        </>}
        {page==='scanner'&&<><p className="subtitle">{t('scanHint')}</p><section className="panel form-panel"><PanelTitle title={t('scanTitle')} icon={<ScanSearch/>}/><label>{t('inputLabel')}</label><textarea value={textValue} onChange={e=>setTextValue(e.target.value)} placeholder={t('placeholder')} rows={7}/><div className="form-footer"><span className="muted">Server-side scan · Synthetic test data recommended</span><button className="primary" disabled={busy||!textValue.trim()||!api} onClick={()=>runScan()}>{busy?'…':t('runScan')}</button></div></section>
          {scan&&<section className="panel result-panel"><PanelTitle title={t('decision')} icon={<Shield/>}/><div className={`decision ${decisionClass(scan.decision)}`}>{t(scan.decision.toLowerCase() as Key)}</div><p className="muted">{scan.policy}</p><h3>{t('matched')} ({scan.findings.length})</h3>{scan.findings.length?scan.findings.map((f,i)=><div className="finding" key={i}><span className={`severity ${f.severity.toLowerCase()}`}>{t(f.severity.toLowerCase() as Key)}</span><b>{f.type}</b><code>{f.masked}</code></div>):<p className="muted">{t('noFindings')}</p>}{scan.safeText&&<div className="safe-output"><b>Redacted output</b><p>{scan.safeText}</p></div>}</section>}</>}
        {page==='gate'&&<><p className="subtitle">{t('gateHint')}</p><section className="panel form-panel"><PanelTitle title={t('gateTitle')} icon={<Bot/>}/><div className="field-grid"><div><label>{t('agent')}</label><input value={agent} onChange={e=>setAgent(e.target.value)}/></div><div><label>{t('action')}</label><select value={action} onChange={e=>setAction(e.target.value)}><option value="read_report">read_report</option><option value="send_email">send_email</option><option value="delete_customer_records">delete_customer_records</option><option value="export_customer_data">export_customer_data</option></select></div><div className="wide"><label>{t('resource')}</label><input value={resource} onChange={e=>setResource(e.target.value)}/></div></div><div className="form-footer"><span className="muted">Only a harmless demo authorization check; no external tool is executed.</span><button className="primary" disabled={busy||!api} onClick={authorize}>{t('checkAction')}</button></div></section>{gate&&<section className="panel result-panel"><PanelTitle title={t('result')} icon={<Shield/>}/><div className={`decision ${gate.allowed?'allow':'block'}`}>{gate.allowed?t('allowed'):t('denied')}</div><p>{gate.reason}</p><p className="muted">Execution status: {gate.executed?'executed':'not executed'}</p></section>}</>}
        {page==='policies'&&<><p className="subtitle">{t('policyHint')}</p><section className="panel"><PanelTitle title={t('policyTitle')} icon={<SlidersHorizontal/>}/><div className="policy-row"><span className="policy-badge block">BLOCK</span><div><b>Credential pattern detected</b><small>Priority 10 · Prevent sensitive credential handling</small></div></div><div className="policy-row"><span className="policy-badge redact">REDACT</span><div><b>Personal data pattern detected</b><small>Priority 20 · Mask matched values</small></div></div><div className="policy-row"><span className="policy-badge review">REVIEW</span><div><b>High-risk agent action</b><small>Priority 30 · Require explicit approval</small></div></div><div className="policy-row"><span className="policy-badge allow">ALLOW</span><div><b>No matching security rule</b><small>Priority 100 · Permit low-risk test actions</small></div></div><p className="muted">These are server-defined starter policies. Production policy administration and user roles are not included in this MVP.</p></section></>}
        {page==='audit'&&<><p className="subtitle">{t('auditHint')}</p><section className="panel"><PanelTitle title={t('auditTitle')} icon={<ClipboardList/>}/>{audit.length?audit.map(x=><AuditRow key={x.id} item={x}/>):<div className="empty">{t('clean')}</div>}</section></>}
        <footer>ActionGuard AI <span>·</span> MVP 0.1.0 <span>·</span> Security decisions are enforced by the local API</footer>
      </div>
    </main>
  </div>;
}
function Stat({icon,label,value,tone}:{icon:React.ReactNode;label:string;value:string|number;tone:string}){return <div className="stat-card"><div className={`stat-icon ${tone}`}>{icon}</div><div><small>{label}</small><strong>{value}</strong></div></div>}
function PanelTitle({title,icon}:{title:string;icon:React.ReactNode}){return <div className="panel-title"><span>{icon}</span><h2>{title}</h2></div>}
function AuditRow({item}:{item:Audit}){return <div className="audit-row"><div className="audit-icon"><Clock3 size={16}/></div><div className="audit-main"><b>{item.event.replaceAll('_',' ')}</b><small>{item.rule}</small></div><span className={`outcome ${item.outcome.toLowerCase()}`}>{item.outcome}</span><time>{new Date(item.created_at).toLocaleString()}</time></div>}
