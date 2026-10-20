import React from 'react';
import { BookOpen, Shield, Target, Layers, Activity, CheckCircle, FileText, ArrowRight } from 'lucide-react';

const DocumentationTab: React.FC = () => {
  return (
    <div className="max-w-5xl mx-auto space-y-8 py-2">
      <div className="bg-[#0D111A] border border-slate-800 p-6 rounded-xl">
        <div className="flex items-center gap-2.5 mb-2">
          <BookOpen className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-bold text-white tracking-tight">Audit Methodology & Security Framework Alignment</h2>
        </div>
        <p className="text-slate-400 text-xs leading-relaxed max-w-3xl">
          RuleGuardX provides deterministic, offline firewall security audits. The engine parses access control lists, correlates rule hierarchies, and flags excessive exposure using standardized threat modeling and zero-trust principles.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <section className="bg-[#0D111A] border border-slate-800 p-5 rounded-xl space-y-4 shadow-xs">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <Target className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">Risk Scoring Model (0 - 100)</h3>
          </div>
          <div className="space-y-3 text-xs text-slate-300">
            <p className="text-slate-400 text-[11px] leading-relaxed">
              The composite Policy Risk Score represents the weighted severity of all active allow rules based on exploitability, blast radius, and protocol vulnerability:
            </p>
            <div className="space-y-2">
              <div className="flex items-start gap-3 p-2.5 bg-slate-900 rounded-lg border border-slate-800/80">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-500/10 text-rose-400 border border-rose-500/20 shrink-0">CRITICAL · 100</span>
                <span className="text-[11px] text-slate-300">Unrestricted ANY/ANY ingress or internet exposure of management ports (SSH 22, RDP 3389, Telnet 23).</span>
              </div>
              <div className="flex items-start gap-3 p-2.5 bg-slate-900 rounded-lg border border-slate-800/80">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-orange-500/10 text-orange-400 border border-orange-500/20 shrink-0">HIGH · 80+</span>
                <span className="text-[11px] text-slate-300">Broad subnet targets (/16 or larger) or plaintext authentication protocols (FTP, HTTP, SNMPv1/v2).</span>
              </div>
              <div className="flex items-start gap-3 p-2.5 bg-slate-900 rounded-lg border border-slate-800/80">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-500/10 text-amber-400 border border-amber-500/20 shrink-0">MEDIUM · 50-70</span>
                <span className="text-[11px] text-slate-300">Logical conflicts between rules or overly permissive internal lateral movement pathways.</span>
              </div>
              <div className="flex items-start gap-3 p-2.5 bg-slate-900 rounded-lg border border-slate-800/80">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-800 text-slate-300 border border-slate-700 shrink-0">LOW · &lt; 40</span>
                <span className="text-[11px] text-slate-300">Rule hygiene issues, shadowed rules, dead configurations, and unreferenced object definitions.</span>
              </div>
            </div>
          </div>
        </section>

        <section className="bg-[#0D111A] border border-slate-800 p-5 rounded-xl space-y-4 shadow-xs">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <Shield className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">Zero-Trust Baseline Principles</h3>
          </div>
          <div className="space-y-3.5">
            <DocItem 
              title="Principle of Least Privilege" 
              desc="Access rules must define specific destination ports and application IDs. Rules configured with ANY service are flagged for explicit service scoping."
            />
            <DocItem 
              title="Boundary Segmentation" 
              desc="Traffic crossing between public, DMZ, and internal enclaves must be strictly constrained to prevent multi-hop lateral expansion."
            />
            <DocItem 
              title="Deterministic Evaluation" 
              desc="Policies should be organized to avoid shadowing and contradictory actions, ensuring predictable rule execution by stateful firewalls."
            />
          </div>
        </section>
      </div>

      <section className="bg-[#0D111A] border border-slate-800 p-5 rounded-xl space-y-4 shadow-xs">
        <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
          <Layers className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">Policy Hygiene & Structural Health</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <HygieneDetail 
            title="Shadowed Rules"
            desc="A rule placed after another broader rule that already covers identical or superset traffic. The shadowed rule will never receive traffic."
            impact="Increases latency, bloats rulebases, and causes auditing confusion."
          />
          <HygieneDetail 
            title="Policy Logic Conflicts"
            desc="Overlapping source/destination tuples where one rule permits and another denies, introducing non-deterministic execution depending on rule ordering."
            impact="Creates unintended security leakage or service outage risks."
          />
          <HygieneDetail 
            title="Latent Administrative Risk"
            desc="High-criticality rules that are currently disabled in policy. If inadvertently re-enabled, they immediately expose vulnerable services."
            impact="Can be weaponized as easy pivot points by adversaries with console access."
          />
        </div>
      </section>

      <section className="bg-[#0D111A] border border-slate-800 p-5 rounded-xl space-y-4 shadow-xs">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">Framework Compliance Mapping</h3>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
          RuleGuardX audit findings reference standard control requirements from globally recognized cybersecurity authorities:
        </p>
        <div className="flex flex-wrap gap-2.5 pt-1">
          <ComplianceBadge label="NIST SP 800-41 Rev 1" detail="Firewall Guidelines" />
          <ComplianceBadge label="MITRE ATT&CK Enterprise" detail="T1190 & T1021" />
          <ComplianceBadge label="CIS Controls v8" detail="Control 4 & 12" />
          <ComplianceBadge label="PCI DSS v4.0" detail="Req 1.2 & 1.3" />
          <ComplianceBadge label="SOC 2 Type II" detail="CC6.6 Network Security" />
        </div>
      </section>
    </div>
  );
};

const DocItem = ({ title, desc }: { title: string, desc: string }) => (
  <div className="space-y-1">
    <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wide">{title}</h4>
    <p className="text-xs text-slate-400 leading-relaxed">{desc}</p>
  </div>
);

const HygieneDetail = ({ title, desc, impact }: { title: string, desc: string, impact: string }) => (
  <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800 space-y-2.5">
    <h4 className="text-xs font-bold text-cyan-400">{title}</h4>
    <p className="text-xs text-slate-300 leading-relaxed">{desc}</p>
    <div className="pt-2 border-t border-slate-800/80">
      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-0.5">Operational Risk</span>
      <p className="text-[11px] text-slate-400">{impact}</p>
    </div>
  </div>
);

const ComplianceBadge = ({ label, detail }: { label: string, detail: string }) => (
  <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs">
    <span className="font-semibold text-white">{label}</span>
    <span className="text-slate-500 text-[10px]">({detail})</span>
  </div>
);

export default DocumentationTab;