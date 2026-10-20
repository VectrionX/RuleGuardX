
import { FirewallRule, AnalysisFinding, Severity, AnalysisResults, InsecurePortSetting, InsecureServiceSetting, ServiceObject, NetworkObject } from '../types';

const SECURITY_KNOWLEDGE_BASE = {
  ANY_ANY: {
    explanation: "Critical security control failure. Allowing 'ANY' source, destination, and service creates a 'Transparent Firewall' state. This violates NIST SP 800-53 AC-4.",
    recommendation: "Immediate Remediation Required: Deconstruct the rule into specific explicit 'Allow' lists."
  },
  ANY_SOURCE: {
    explanation: "Unrestricted Ingress Exposure. Source 'ANY' implies the rule is reachable from any point in the routed network.",
    recommendation: "Restrict the source to specific authorized CIDR blocks or Geofenced IP ranges."
  },
  ANY_DESTINATION: {
    explanation: "Blast Radius Escalation. Destination 'ANY' permits traffic to traverse into sensitive internal zones, facilitating lateral movement.",
    recommendation: "Narrow the destination to the specific IP address or host group required."
  },
  ANY_PORT: {
    explanation: "Unrestricted Port Access (ANY). This rule allows all 65,535 ports, making the firewall effectively transparent for this traffic flow.",
    recommendation: "Restrict the destination port to the specific service required for business operations."
  },
  LARGE_SUBNET: (size: number) => ({
    explanation: `Excessive Blast Radius (/${size}). This broad trust relationship facilitates Network Service Discovery and violates Zero Trust principles.`,
    recommendation: "Segment the network into smaller subnets (typically /24 or smaller)."
  })
};

const SERVICE_MAP: Record<string, number> = {
  'ssh': 22, 'telnet': 23, 'http': 80, 'https': 443, 'ftp': 21, 'rdp': 3389,
  'mysql': 3306, 'mssql': 1433, 'smb': 445, 'dns': 53, 'ntp': 123, 'snmp': 161,
  'ldap': 389, 'ldaps': 636, 'smtp': 25, 'smtps': 465, 'imap': 143, 'imaps': 993,
  'pop3': 110, 'pop3s': 995, 'vnc': 5900, 'winrm': 5985, 'winrm-s': 5986,
  'oracle': 1521, 'mongodb': 27017, 'postgresql': 5432
};

const getCidrSize = (addr: string, networkObjectMap: Map<string, NetworkObject> = new Map()): number => {
  if (!addr) return 32;
  const parts = addr.split(/[,\s;]+/).filter(p => p.trim());
  let smallestCidr = 32;

  for (const part of parts) {
    let clean = part.trim().toLowerCase();
    
    // Resolve network object if it exists
    const netObj = networkObjectMap.get(clean);
    if (netObj) {
      // Recursively evaluate the resolved value in case it has multiple subnets
      const resolvedSize = getCidrSize(netObj.value.toLowerCase(), networkObjectMap);
      smallestCidr = Math.min(smallestCidr, resolvedSize);
      continue;
    }

    if (clean === 'any' || clean === '0.0.0.0/0') return 0; 
    if (clean.includes('/')) {
      const cidrPart = clean.split('/')[1];
      const cidr = parseInt(cidrPart, 10);
      if (!isNaN(cidr)) smallestCidr = Math.min(smallestCidr, cidr);
    } 
  }
  return smallestCidr;
};

/**
 * Enhanced Precision Port Parser.
 * Handles: 
 * - tcp-80, udp-53 (Mixed)
 * - 80,443,21 (Lists)
 * - tcp-77-82 (Ranges with prefix)
 * - 400-450 (Ranges)
 */
export const parsePortsAndServices = (portStr: string): (number | string)[] => {
  if (portStr === undefined || portStr === null || portStr.toString().trim() === "") return [-1];
  
  const raw = portStr.toString().trim();
  const clean = raw.toLowerCase();
  
  // Stricter wildcard detection: 'all' removed from here so it can be a Service Object
  if (clean === 'any' || clean === '*') return [-1];
  
  const sanitized = raw.replace(/[\s;/]+/g, ',');
  const parts = sanitized.split(',').filter(p => p.trim().length > 0);
  const result = new Set<number | string>();
  
  parts.forEach(p => {
    let token = p.toLowerCase().trim();

    // 1. Handle Ranges with optional prefix (e.g. tcp-77-82 or 400-450)
    const rangeMatch = token.match(/(?:[a-z]+-)?(\d+)-(\d+)$/i);
    if (rangeMatch) {
      const start = parseInt(rangeMatch[1], 10);
      const end = parseInt(rangeMatch[2], 10);
      if (!isNaN(start) && !isNaN(end)) {
        if (end - start > 500) {
          result.add(-1); 
        } else {
          for (let i = start; i <= end; i++) result.add(i);
        }
        return;
      }
    }

    // 2. Handle Protocol Prefixed Single Ports (e.g. tcp-80)
    const protoMatch = token.match(/^(?:tcp|udp|icmp|service)-(\d+)$/i);
    if (protoMatch) {
      result.add(parseInt(protoMatch[1], 10));
      return;
    }

    // 3. Handle Service Names (e.g. ssh, http)
    if (SERVICE_MAP[token]) {
      result.add(SERVICE_MAP[token]);
      return;
    }

    // 4. Handle Bare Numbers (e.g. 80)
    const bareNum = parseInt(token, 10);
    if (!isNaN(bareNum)) {
      result.add(bareNum);
    } else {
      // It's a named object (like "all" or "web_servers")
      result.add(token);
    }
  });
  
  return Array.from(result);
};

export const analyzeRules = (
  rules: FirewallRule[], 
  portSettings: InsecurePortSetting[],
  serviceSettings: InsecureServiceSetting[] = [],
  serviceObjectMap: Map<string, ServiceObject> = new Map(),
  networkObjectMap: Map<string, NetworkObject> = new Map()
): AnalysisResults => {
  const findings: AnalysisFinding[] = [];
  const hygiene: AnalysisFinding[] = [];

  const activeInsecurePorts = new Map<number, InsecurePortSetting>();
  portSettings.filter(s => s.enabled).forEach(s => activeInsecurePorts.set(s.port, s));

  const activeInsecureServices = new Map<string, InsecureServiceSetting>();
  serviceSettings.filter(s => s.enabled).forEach(s => activeInsecureServices.set(s.name.toLowerCase(), s));

  rules.forEach((rule, index) => {
    const isAllow = rule.action === 'ALLOW';
    if (!isAllow) return;

    const mixedPorts = parsePortsAndServices(rule.destinationPort);
    const srcCidr = getCidrSize(rule.source, networkObjectMap);
    const dstCidr = getCidrSize(rule.destination, networkObjectMap);
    const hasAnyPort = mixedPorts.includes(-1);

    const isAnySource = srcCidr === 0;
    const isAnyDest = dstCidr === 0;

    // --- 1. GLOBAL EXPOSURE ---
    if (hasAnyPort) {
      findings.push({ 
        ruleId: rule.id, ruleName: rule.name, category: 'Excessive Exposure', score: 85, severity: 'HIGH',
        explanation: SECURITY_KNOWLEDGE_BASE.ANY_PORT.explanation,
        recommendation: SECURITY_KNOWLEDGE_BASE.ANY_PORT.recommendation
      });
    }

    if (isAnySource || isAnyDest) {
      const anyDimensions = (isAnySource ? 1 : 0) + (isAnyDest ? 1 : 0) + (hasAnyPort ? 1 : 0);
      if (anyDimensions >= 3) {
        findings.push({ 
          ruleId: rule.id, ruleName: rule.name, category: 'Excessive Exposure', score: 100, severity: 'CRITICAL',
          explanation: SECURITY_KNOWLEDGE_BASE.ANY_ANY.explanation, recommendation: SECURITY_KNOWLEDGE_BASE.ANY_ANY.recommendation 
        });
      } else if (isAnySource) {
        findings.push({ 
          ruleId: rule.id, ruleName: rule.name, category: 'Excessive Exposure', score: 85, severity: 'HIGH',
          explanation: SECURITY_KNOWLEDGE_BASE.ANY_SOURCE.explanation, recommendation: SECURITY_KNOWLEDGE_BASE.ANY_SOURCE.recommendation 
        });
      } else if (isAnyDest) {
        findings.push({ 
          ruleId: rule.id, ruleName: rule.name, category: 'Excessive Exposure', score: 80, severity: 'HIGH',
          explanation: SECURITY_KNOWLEDGE_BASE.ANY_DESTINATION.explanation, recommendation: SECURITY_KNOWLEDGE_BASE.ANY_DESTINATION.recommendation 
        });
      }
    }

    // --- 2. SUBNET SCOPE ---
    if (srcCidr > 0 && srcCidr <= 16) {
      const kb = SECURITY_KNOWLEDGE_BASE.LARGE_SUBNET(srcCidr);
      findings.push({ 
        ruleId: rule.id, ruleName: rule.name, category: 'Subnet Scope', score: srcCidr <= 8 ? 100 : 80, 
        severity: srcCidr <= 8 ? 'CRITICAL' : 'HIGH', explanation: `Source ${kb.explanation}`, recommendation: kb.recommendation 
      });
    }
    if (dstCidr > 0 && dstCidr <= 16) {
      const kb = SECURITY_KNOWLEDGE_BASE.LARGE_SUBNET(dstCidr);
      findings.push({ 
        ruleId: rule.id, ruleName: rule.name, category: 'Subnet Scope', score: dstCidr <= 8 ? 100 : 80, 
        severity: dstCidr <= 8 ? 'CRITICAL' : 'HIGH', explanation: `Destination ${kb.explanation}`, recommendation: kb.recommendation 
      });
    }

    // --- 3. INSECURE PORTS & SERVICE OBJECTS ---
    const checkItem = (item: number | string, context: string) => {
      if (typeof item === 'number') {
        if (item === -1) return;
        const setting = activeInsecurePorts.get(item);
        if (setting) {
          findings.push({
            ruleId: rule.id, ruleName: rule.name, category: 'Insecure Port',
            score: setting.criticality === 'CRITICAL' ? 100 : 90,
            severity: setting.criticality,
            explanation: `Rule allows ${setting.label} (Port ${item}) ${context}. Inherently insecure protocol.`,
            recommendation: `Transition to encrypted alternatives (SSH, HTTPS).`
          });
        }
      } else {
        const itemLower = item.toLowerCase();
        
        // Check 1: Explicitly flagged in settings
        const setting = activeInsecureServices.get(itemLower);
        if (setting) {
          findings.push({
            ruleId: rule.id, ruleName: rule.name, category: 'Insecure Service Object',
            score: 90, severity: setting.criticality,
            explanation: `Rule uses object '${item}', which is explicitly flagged as insecure in settings.`,
            recommendation: `Restrict or decommission this service object.`
          });
        }

        // Check 2: Recursive Deep Search (Inside Service Objects CSV)
        const dynamicObj = serviceObjectMap.get(itemLower);
        if (dynamicObj) {
          dynamicObj.ports.forEach(p => {
            if (typeof p === 'number') {
              const pSetting = activeInsecurePorts.get(p);
              if (pSetting) {
                findings.push({
                  ruleId: rule.id, ruleName: rule.name, category: 'Insecure Service Object',
                  score: 95, severity: pSetting.criticality,
                  explanation: `Object '${item}' contains insecure port ${p} (${pSetting.label}).`,
                  recommendation: `Remove insecure port ${p} from the service object '${item}' definition.`
                });
              }
            }
          });
        }
      }
    };

    mixedPorts.forEach(item => checkItem(item, "via port definition"));
    
    if (rule.service) {
       const serviceTokens = rule.service.split(/[,\s;]+/).filter(t => t.trim());
       serviceTokens.forEach(t => {
         const parsed = parsePortsAndServices(t);
         parsed.forEach(pt => checkItem(pt, `via service object '${t}'`));
       });
    }
  });

  // Policy Hygiene Check
  rules.forEach((rule, index) => {
    if (!rule.enabled) return;
    const shadowedBy = rules.slice(0, index).find(prev => 
      prev.enabled && prev.action === rule.action &&
      (prev.source.toLowerCase() === 'any' || prev.source === rule.source) &&
      (prev.destination.toLowerCase() === 'any' || prev.destination === rule.destination) &&
      (prev.protocol.toLowerCase() === 'any' || prev.protocol === rule.protocol) &&
      (prev.destinationPort.toLowerCase() === 'any' || prev.destinationPort === rule.destinationPort)
    );
    if (shadowedBy) {
      hygiene.push({
        ruleId: rule.id, ruleName: rule.name, category: 'Policy Hygiene', score: 20, severity: 'INFORMATIONAL',
        explanation: `Rule is shadowed by ID ${shadowedBy.id}.`,
        recommendation: "Remove redundant entry to reduce policy complexity."
      });
    }
  });

  return {
    rules, findings, hygiene,
    summary: {
      totalRules: rules.length,
      enabledRules: rules.filter(r => r.enabled).length,
      criticalFindings: findings.filter(f => f.severity === 'CRITICAL').length,
      highFindings: findings.filter(f => f.severity === 'HIGH').length,
      mediumFindings: findings.filter(f => f.severity === 'MEDIUM').length,
      lowFindings: findings.filter(f => f.severity === 'LOW').length,
      averageRiskScore: findings.length > 0 ? Math.round(findings.reduce((a, b) => a + b.score, 0) / findings.length) : 0
    }
  };
};
