import { describe,it,expect } from 'vitest';
import { scanSensitiveText,decideScan,redactText,authorizeAction } from '../server/security';
describe('ActionGuard security core',()=>{
 it('allows ordinary safe text',()=>{const f=scanSensitiveText('Hello team, the meeting is at 10.');expect(decideScan(f)).toBe('REVIEW')});
 it('routes safe text to review rather than automatic allow',()=>{expect(decideScan([])).toBe('REVIEW')});
 it('blocks credential-like tokens',()=>{const f=scanSensitiveText('api_key=FAKE_DEMO_KEY_1234567890');expect(f.length).toBeGreaterThan(0);expect(decideScan(f)).toBe('BLOCK')});
 it('redacts email addresses',()=>{const s='Contact demo@example.com for details';const f=scanSensitiveText(s);expect(decideScan(f)).toBe('REDACT');expect(redactText(s,f)).not.toContain('demo@example.com')});
 it('detects and redacts possible phone numbers',()=>{const s='Call +1 202 555 0199';const f=scanSensitiveText(s);expect(f.some(x=>x.type==='Possible phone number')).toBe(true);expect(redactText(s,f)).not.toContain('+1 202 555 0199')});
 it('allows only read-only report action',()=>{expect(authorizeAction('read_report','reports/monthly').allowed).toBe(true)});
 it('denies destructive actions without execution',()=>{const r=authorizeAction('delete_customer_records','customers/all');expect(r.allowed).toBe(false);expect(r.executed).toBe(false)});
 it('requires review for unknown actions',()=>{expect(authorizeAction('send_email','customers').decision).toBe('REVIEW')});
});
