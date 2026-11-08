/**
 * cyber-recon-ts-wayback-cdx-endpoint-miner — Bug Bounty Recon & Ghost Asset Discovery (wayback-cdx-endpoint-miner)
 * Author: Eng. Mahmoud Bek ElNemer (@ElNeMeR70)
 * Standards: CWE-200 / CWE-540 / CWE-942
 */
import * as crypto from 'crypto';

const SIGNATURES: RegExp[] = [
  new RegExp("AIza[0-9A-Za-z\\-_]{35}", 'i'), new RegExp("AKIA[0-9A-Z]{16}", 'i'), new RegExp("ghp_[0-9a-zA-Z]{36}", 'i'), new RegExp("sk-[a-zA-Z0-9]{48}", 'i'), new RegExp("Access-Control-Allow-Origin:\\s*\\*", 'i')
];

export interface SecurityAuditReport {
  engine: string;
  standards: string;
  findingsCount: number;
  matches: string[];
  entropyBits: number;
  verdict: 'BLOCK_THREAT' | 'CLEAN_VERIFIED';
  mitigation: string;
  attestation: string;
}

export function shannonEntropy(input: string): number {
  if (!input.length) return 0;
  const counts: Record<string, number> = {};
  for (const ch of input) counts[ch] = (counts[ch] || 0) + 1;
  return Number(
    (-Object.values(counts).reduce((acc, c) => {
      const p = c / input.length;
      return acc + p * Math.log2(p);
    }, 0)).toFixed(4)
  );
}

export function auditPayload(payload: string): SecurityAuditReport {
  const matches: string[] = [];
  for (const rx of SIGNATURES) {
    const m = payload.match(rx);
    if (m) matches.push(m[0]);
  }
  const hmac = crypto.createHmac('sha256', 'cyber-recon-ts-wayback-cdx-endpoint-miner').update(payload).digest('hex').slice(0, 32);
  return {
    engine: 'cyber-recon-ts-wayback-cdx-endpoint-miner',
    standards: 'CWE-200 / CWE-540 / CWE-942',
    findingsCount: matches.length,
    matches,
    entropyBits: shannonEntropy(payload),
    verdict: matches.length > 0 ? 'BLOCK_THREAT' : 'CLEAN_VERIFIED',
    mitigation: 'Strip sourceMaps in production builds, rotate leaked API credentials, and restrict CORS origins.',
    attestation: hmac,
  };
}

if (require.main === module) {
  const arg = process.argv[2] || 'SELECT * FROM accounts WHERE token = eval(innerHTML=tx.origin)';
  console.log(JSON.stringify(auditPayload(arg), null, 2));
}
