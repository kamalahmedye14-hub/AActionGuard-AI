import express from 'express';
import cors from 'cors';
import { z } from 'zod';
import { db } from './db';
import { scanSensitiveText, decideScan, redactText, authorizeAction } from './security';
const app=express();
app.disable('x-powered-by');
app.use((req,res,next)=>{
 res.setHeader('X-Content-Type-Options','nosniff');
 res.setHeader('X-Frame-Options','DENY');
 res.setHeader('Referrer-Policy','no-referrer');
 res.setHeader('Cache-Control','no-store');
 next();
});
const allowedOrigins=(process.env.CORS_ORIGIN||'http://localhost:5173').split(',').map(x=>x.trim()).filter(Boolean);
app.use(cors({origin(origin,callback){ if(!origin||allowedOrigins.includes(origin)) return callback(null,true); return callback(new Error('Origin not allowed')); }}));
app.use(express.json({limit:'16kb'}));
// Lightweight per-process throttle for the MVP; use a shared store at production scale.
const requestCounts=new Map<string,{count:number;resetAt:number}>();
app.use('/api',(req,res,next)=>{
 const now=Date.now(); const key=req.ip||'unknown'; let entry=requestCounts.get(key);
 if(!entry||entry.resetAt<=now){entry={count:0,resetAt:now+60_000};requestCounts.set(key,entry);}
 entry.count++;
 if(entry.count>60) return res.status(429).json({error:'Too many requests. Try again in a minute.'});
 if(requestCounts.size>5000){for(const [ip,value] of requestCounts) if(value.resetAt<=now) requestCounts.delete(ip);}
 next();
});
function audit(event:string,outcome:string,rule:string){db.prepare('INSERT INTO audit_events(event,outcome,rule) VALUES(?,?,?)').run(event,outcome,rule);}
app.get('/api/health',(_req,res)=>res.json({ok:true,service:'ActionGuard AI API',version:'0.1.0'}));
app.get('/api/audit',(_req,res)=>res.json(db.prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT 50').all()));
app.get('/api/policies',(_req,res)=>res.json(db.prepare('SELECT id,name,action,priority,enabled FROM policies ORDER BY priority ASC').all()));
app.post('/api/scan',(req,res)=>{
 const parsed=z.object({text:z.string().min(1).max(12000)}).safeParse(req.body);
 if(!parsed.success)return res.status(400).json({error:'Text must be between 1 and 12000 characters'});
 const findings=scanSensitiveText(parsed.data.text);
 const decision=decideScan(findings);
 const safeText=decision==='REDACT'?redactText(parsed.data.text,findings):undefined;
 const rule=decision==='ALLOW'?'Explicit allow policy matched':decision==='BLOCK'?'Credential pattern detected':decision==='REDACT'?'Sensitive personal-data pattern detected':'No matching security rule; manual review required';
 audit('DATA_SCAN',decision,rule);
 res.json({decision,findings:findings.map(({type,severity,masked})=>({type,severity,masked})),safeText,policy:rule});
});
app.post('/api/authorize-action',(req,res)=>{
 const parsed=z.object({agent:z.string().min(1).max(100),action:z.string().min(1).max(100),resource:z.string().min(1).max(200)}).safeParse(req.body);
 if(!parsed.success)return res.status(400).json({error:'Invalid action request'});
 const result=authorizeAction(parsed.data.action,parsed.data.resource);
 audit('AGENT_ACTION_CHECK',result.decision,result.reason);
 res.json({...result,agent:parsed.data.agent});
});
const port=Number(process.env.PORT||4000);
app.listen(port,'0.0.0.0',()=>console.log(`ActionGuard API listening on ${port}`));
