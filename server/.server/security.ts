بexport type Decision = 'ALLOW'|'BLOCK'|'REDACT'|'REVIEW';
export type Finding = { type:string; severity:'HIGH'|'MEDIUM'; masked:string; start:number; end:number };
const patterns: Array<{type:string; regex:RegExp; severity:'HIGH'|'MEDIUM'}> = [
 {type:'Credential-like token',regex:/(?:api[_-]?key|secret|token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{12,})/gi,severity:'HIGH'},
 {type:'Email address',regex:/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,severity:'MEDIUM'},
 {type:'Possible phone number',regex:/\b(?:\+?\d[\d\s().-]{8,}\d)\b/g,severity:'MEDIUM'}
];
export function scanSensitiveText(input:string):Finding[]{
 const findings:Finding[]=[];
 for(const p of patterns){ p.regex.lastIndex=0; let m:RegExpExecArray|null;
  while((m=p.regex.exec(input))!==null){ const raw=m[1]??m[0]; const start=m.index+(m[1]?m[0].indexOf(m[1]):0); const end=start+raw.length;
   const masked=raw.length>8?`${raw.slice(0,3)}••••${raw.slice(-3)}`:'••••';
   findings.push({type:p.type,severity:p.severity,masked,start,end});
   if(m[0].length===0)p.regex.lastIndex++;
  }
 }
 return findings.sort((a,b)=>a.start-b.start);
}
export function redactText(input:string,findings:Finding[]):string{
 let output=input;
 for(const f of [...findings].sort((a,b)=>b.start-a.start)) output=output.slice(0,f.start)+'[REDACTED]'+output.slice(f.end);
 return output;
}
export function decideScan(findings:Finding[]):Decision{
 if(findings.some(f=>f.type==='Credential-like token')) return 'BLOCK';
 if(findings.length) return 'REDACT';
 return 'REVIEW';
}
const allowedActions = new Set(['read_report']);
const deniedActions = new Set(['delete_customer_records','export_customer_data']);
export function authorizeAction(action:string,resource:string){
 if(!action.trim()||!resource.trim()) return {allowed:false,reason:'Action and resource are required',executed:false,decision:'BLOCK' as Decision};
 if(deniedActions.has(action)) return {allowed:false,reason:'Destructive or sensitive action is not enabled in this MVP',executed:false,decision:'BLOCK' as Decision};
 if(allowedActions.has(action)&&resource.startsWith('reports/')) return {allowed:true,reason:'Read-only report permission granted',executed:false,decision:'ALLOW' as Decision};
 return {allowed:false,reason:'No matching permission policy',executed:false,decision:'REVIEW' as Decision};
}
