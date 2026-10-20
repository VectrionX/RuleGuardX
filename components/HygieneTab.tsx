import React from 'react';
import { AnalysisFinding } from '../types';
import { Layers, AlertTriangle, ShieldX, Info, HelpCircle } from 'lucide-react';

interface HygieneTabProps {
  hygiene: AnalysisFinding[];
}

const HYGIENE_DEFINITIONS = {
  'Shadowed Rules': 'A redundancy issue where a rule is placed after another more general rule that already handles all its traffic. The shadowed rule is never reached by traffic, introducing dead security policy.',
  'Logic Conflicts': 'Ambiguity in policy enforcement where multiple rules overlap in criteria (source, destination, port) but specify different actions (Allow vs Deny). Device behavior becomes non-deterministic.',
  'Latent Risk': 'Security exposure that is present but currently inactive, such as high-risk rules that are disabled. These represent a primary target for defense evasion techniques.',
  'Policy Hygiene': 'Maintenance issues that do not immediately break security but degrade rulebase maintainability, such as redundant or empty definitions.',
  'Correlation Error': 'Critical logical overlapping where the firewall cannot reliably determine which action to take, potentially leading to unauthorized permit bypasses.'
};

const HygieneTab: React.FC<HygieneTabProps> = ({ hygiene }) => {
  return (
    <div className="space-y-6">
      <div className="bg-[#0D111A] p-6 rounded-xl border border-slate-800">
        <div className="flex items-center gap-2.5 mb-1.5">
          <Layers className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-bold text-white tracking-tight">Policy Correlation & Hygiene Analysis</h2>
        </div>
        <p className="text-slate-400 text-xs leading-relaxed max-w-3xl">
          Detection of shadowed, redundant, and conflicting firewall rules. Optimizing rule ordering reduces processing overhead and eliminates policy ambiguity.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <HygieneSummary 
           title="Shadowed Rules" 
           count={hygiene.filter(h => h.explanation.includes('Shadowed')).length}
           icon={Layers}
           badgeColor="text-amber-400 bg-amber-500/10 border-amber-500/20"
           description={HYGIENE_DEFINITIONS['Shadowed Rules']}
        />
        <HygieneSummary 
           title="Logic Conflicts" 
           count={hygiene.filter(h => h.category === 'Correlation Error').length}
           icon={ShieldX}
           badgeColor="text-rose-400 bg-rose-500/10 border-rose-500/20"
           description={HYGIENE_DEFINITIONS['Logic Conflicts']}
        />
        <HygieneSummary 
           title="Latent Disabled Risks" 
           count={hygiene.filter(h => h.explanation.includes('Disabled')).length}
           icon={AlertTriangle}
           badgeColor="text-sky-400 bg-sky-500/10 border-sky-500/20"
           description={HYGIENE_DEFINITIONS['Latent Risk']}
        />
      </div>

      <div className="space-y-3">
        {hygiene.length > 0 ? hygiene.map((h, i) => (
          <div key={i} className="bg-[#0D111A] border border-slate-800 p-5 rounded-xl flex flex-col md:flex-row items-start md:items-center gap-4 hover:border-slate-700 transition-colors">
            <div className={`p-2.5 rounded-lg border ${
              h.category === 'Correlation Error' 
                ? 'bg-rose-500/10 border-rose-500/20 text-rose-400' 
                : 'bg-slate-800/80 border-slate-700/60 text-slate-400'
            }`}>
               <AlertTriangle className="w-5 h-5" />
            </div>

            <div className="flex-1 space-y-1.5">
               <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[10px] font-bold uppercase tracking-wider bg-slate-800 px-2 py-0.5 rounded border border-slate-700 text-slate-300">
                    {h.category}
                  </span>
                  <span className="text-slate-600">·</span>
                  <span className="text-sm font-bold text-white">{h.ruleName}</span>
                  <span className="text-slate-600">·</span>
                  <span className="text-xs font-mono text-slate-400">Rule #{h.ruleId}</span>
               </div>
               <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">{h.explanation}</p>
            </div>

            <div className="w-full md:w-80 bg-slate-900/60 p-3 rounded-lg border border-slate-800/80 shrink-0">
               <div className="flex items-center gap-1.5 mb-1 text-slate-300 text-[10px] font-semibold uppercase tracking-wider">
                 <HelpCircle className="w-3 h-3 text-cyan-400" />
                 <span>Remediation Advice</span>
               </div>
               <p className="text-xs text-slate-300 leading-relaxed font-sans">{h.recommendation}</p>
            </div>
          </div>
        )) : (
          <div className="p-16 text-center text-slate-500 bg-[#0D111A] border border-dashed border-slate-800 rounded-xl">
            <Layers className="w-8 h-8 mx-auto mb-2 text-slate-600" />
            <p className="text-sm font-semibold text-slate-300">No rule hygiene conflicts detected</p>
            <p className="text-xs text-slate-500 mt-0.5">Policy demonstrates clean ordering and no shadowed directives</p>
          </div>
        )}
      </div>
    </div>
  );
};

const HygieneSummary = ({ 
  title, 
  count, 
  icon: Icon, 
  badgeColor, 
  description 
}: { 
  title: string; 
  count: number; 
  icon: any; 
  badgeColor: string; 
  description: string; 
}) => (
  <div className="bg-[#0D111A] p-5 rounded-xl border border-slate-800 flex flex-col justify-between">
    <div className="flex justify-between items-start mb-3">
      <div className="flex items-center gap-2">
        <div className={`p-2 rounded-lg border ${badgeColor}`}>
          <Icon className="w-4 h-4" />
        </div>
        <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">{title}</span>
      </div>
      <span className="text-2xl font-bold font-mono text-white tabular-nums">{count}</span>
    </div>
    <p className="text-[11px] text-slate-400 leading-relaxed mt-1">
      {description}
    </p>
  </div>
);

export default HygieneTab;

