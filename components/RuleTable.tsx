
import React, { useState } from 'react';
import { FirewallRule, AnalysisFinding, Severity, FilterState, FilterClause } from '../types';
import { Shield, ShieldAlert, ShieldCheck, ArrowRight, ChevronDown, ChevronUp, AlertCircle, Info, Filter as FilterIcon, MoreHorizontal, Copy } from 'lucide-react';
import { SEVERITY_COLORS } from '../constants';

interface RuleTableProps {
  rules: FirewallRule[];
  findings: AnalysisFinding[];
  filters: FilterState;
}

const SmartCell: React.FC<{ value: string; label?: string }> = ({ value, label }) => {
  const items = value.split(/[,\s;]+/).filter(i => i.trim().length > 0);
  const showPeeks = items.slice(0, 2);
  const hasMore = items.length > 2;

  return (
    <div className="relative group/cell max-w-full">
      <div className="flex flex-wrap gap-1.5 items-center">
        {showPeeks.map((item, idx) => (
          <span key={idx} className="text-[11px] font-mono tabular-nums bg-slate-900 px-2 py-0.5 rounded border border-slate-700/80 text-slate-200 truncate max-w-[120px]">
            {item}
          </span>
        ))}
        {hasMore && (
          <span className="text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 px-1.5 py-0.5 rounded border border-cyan-500/20 flex items-center cursor-help">
            +{items.length - 2}
          </span>
        )}
        {items.length === 0 && <span className="text-slate-500 italic text-xs">any</span>}
      </div>

      {/* Hover Tooltip */}
      {items.length > 0 && (
        <div className="absolute z-[70] invisible group-hover/cell:visible opacity-0 group-hover/cell:opacity-100 translate-y-1 group-hover/cell:translate-y-0 transition-all duration-150 bottom-full left-0 mb-2 w-max max-w-xs sm:max-w-md bg-[#0D111A] border border-slate-700 rounded-lg shadow-xl p-3">
          <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-2 border-b border-slate-800 pb-1.5 flex justify-between">
            <span>{label || 'Complete Target List'}</span>
            <span className="font-mono text-cyan-400">{items.length} Total</span>
          </div>
          <div className="flex flex-wrap gap-1 max-h-56 overflow-y-auto custom-scrollbar">
            {items.map((item, idx) => (
              <span key={idx} className="text-[11px] font-mono tabular-nums bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-slate-200">
                {item}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

const RuleTable: React.FC<RuleTableProps> = ({ rules, findings, filters }) => {
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);

  const ruleToFindings = React.useMemo(() => {
    const map: Record<string, AnalysisFinding[]> = {};
    findings.forEach(f => {
      if (!map[f.ruleId]) map[f.ruleId] = [];
      map[f.ruleId].push(f);
    });
    return map;
  }, [findings]);

  const ruleRisks = React.useMemo(() => {
    const riskMap: Record<string, { severity: Severity; count: number }> = {};
    Object.entries(ruleToFindings).forEach(([id, ruleFindings]) => {
      let highest: Severity = 'INFORMATIONAL';
      const severities: Severity[] = ['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const findingsArray = ruleFindings as AnalysisFinding[];
      findingsArray.forEach(f => {
        const currentIdx = severities.indexOf(highest);
        const newIdx = severities.indexOf(f.severity);
        if (newIdx > currentIdx) highest = f.severity;
      });
      riskMap[id] = { severity: highest, count: findingsArray.length };
    });
    return riskMap;
  }, [ruleToFindings]);

  const evaluateClause = (rule: FirewallRule, clause: FilterClause, findings: AnalysisFinding[], risk?: { severity: Severity }): boolean => {
    let targetValue: string = '';
    if (clause.field === 'severity') targetValue = risk?.severity || 'INFORMATIONAL';
    else if (clause.field === 'category') targetValue = findings.map(f => f.category).join(' ');
    else targetValue = String((rule as any)[clause.field] || '').toLowerCase();

    const val = clause.value.toLowerCase();
    const tVal = targetValue.toLowerCase();

    if (clause.field === 'destinationPort') {
      const numericTarget = parseInt(targetValue.split(/[,-]/)[0].replace(/[^\d]/g, ''), 10);
      const numericVal = parseInt(val, 10);
      if (!isNaN(numericTarget) && !isNaN(numericVal)) {
        if (clause.operator === 'GREATER_THAN') return numericTarget > numericVal;
        if (clause.operator === 'LESS_THAN') return numericTarget < numericVal;
      }
    }

    switch (clause.operator) {
      case 'CONTAINS': return tVal.includes(val);
      case 'NOT_CONTAINS': return !tVal.includes(val);
      case 'EQUALS': return tVal === val;
      case 'NOT_EQUALS': return tVal !== val;
      case 'STARTS_WITH': return tVal.startsWith(val);
      case 'ENDS_WITH': return tVal.endsWith(val);
      case 'GREATER_THAN': return targetValue > clause.value;
      case 'LESS_THAN': return targetValue < clause.value;
      default: return true;
    }
  };

  const filteredRules = React.useMemo(() => {
    return rules.filter(rule => {
      const risk = ruleRisks[rule.id];
      const ruleFindings = ruleToFindings[rule.id] || [];
      const quickSearchMatch = !filters.quickSearch || [
        rule.name, rule.id, rule.source, rule.destination, rule.destinationPort, rule.description
      ].some(field => String(field).toLowerCase().includes(filters.quickSearch.toLowerCase()));

      if (!quickSearchMatch) return false;
      if (filters.clauses.length === 0) return true;

      let result = evaluateClause(rule, filters.clauses[0], ruleFindings, risk);
      for (let i = 1; i < filters.clauses.length; i++) {
        const clause = filters.clauses[i];
        const clauseResult = evaluateClause(rule, clause, ruleFindings, risk);
        if (clause.logicalOperator === 'AND') result = result && clauseResult;
        else result = result || clauseResult;
      }
      return result;
    });
  }, [rules, filters, ruleRisks, ruleToFindings]);

  const toggleExpand = (id: string) => {
    setExpandedRuleId(expandedRuleId === id ? null : id);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between px-1">
        <div>
          <h3 className="text-lg font-bold text-white tracking-tight">Access Control Rules Directory</h3>
          <p className="text-xs text-slate-400">Structured evaluation of active rule logic and assigned threat levels</p>
        </div>
        <div className="flex items-center gap-3">
           <span className="text-xs font-mono text-slate-400">
             Matched: <strong className="text-white tabular-nums">{filteredRules.length}</strong> / {rules.length}
           </span>
        </div>
      </div>

      <div className="bg-[#0D111A] border border-slate-800 rounded-xl overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[1100px]">
            <thead>
              <tr className="bg-[#101622] text-slate-400 text-[11px] font-semibold uppercase tracking-wider border-b border-slate-800">
                <th className="px-4 py-3.5 w-10 text-center"></th>
                <th className="px-4 py-3.5 w-32">Risk Status</th>
                <th className="px-4 py-3.5 w-52">Rule Name / ID</th>
                <th className="px-4 py-3.5 w-24">Action</th>
                <th className="px-4 py-3.5">Source</th>
                <th className="px-4 py-3.5">Destination</th>
                <th className="px-4 py-3.5 w-44">Service / Port</th>
                <th className="px-4 py-3.5 w-20">Proto</th>
                <th className="px-4 py-3.5 w-10 text-center"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {filteredRules.length > 0 ? filteredRules.map((rule) => {
                const ruleFindings = ruleToFindings[rule.id] || [];
                const risk = ruleRisks[rule.id];
                const isExpanded = expandedRuleId === rule.id;
                const isInsecure = rule.enabled && rule.action === 'ALLOW' && risk;
                
                return (
                  <React.Fragment key={rule.id}>
                    <tr 
                      className={`group transition-colors cursor-pointer ${
                        isExpanded ? 'bg-slate-800/40' : 'hover:bg-slate-800/25'
                      }`}
                      onClick={() => toggleExpand(rule.id)}
                    >
                      <td className="px-4 py-3 text-center">
                        {ruleFindings.length > 0 && (
                          <div className={`p-1 rounded transition-colors inline-flex items-center justify-center ${isExpanded ? 'bg-cyan-500/10 text-cyan-400' : 'text-slate-500 group-hover:text-slate-300'}`}>
                             {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {isInsecure ? (
                          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                              risk.severity === 'CRITICAL' ? 'bg-rose-500/10 border-rose-500/20 text-rose-400' : 
                              risk.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/20 text-orange-400' : 
                              'bg-amber-500/10 border-amber-500/20 text-amber-400'
                          }`}>
                              <ShieldAlert className="w-3 h-3" />
                              <span>{risk.severity}</span>
                          </span>
                        ) : !rule.enabled ? (
                           <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-slate-700 bg-slate-800 text-slate-400 text-[10px] font-semibold uppercase tracking-wider">
                             <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
                             Disabled
                           </span>
                        ) : (
                           <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 text-[10px] font-semibold uppercase tracking-wider">
                             <ShieldCheck className="w-3 h-3" />
                             Secure
                           </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-col">
                          <span className="font-semibold text-slate-200 group-hover:text-white transition-colors">{rule.name}</span>
                          <span className="text-[11px] font-mono text-slate-500 tabular-nums">#{rule.id}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-[11px] font-bold uppercase tracking-wider font-mono ${
                          rule.action === 'ALLOW' 
                            ? 'text-emerald-400' 
                            : 'text-rose-400'
                        }`}>
                          {rule.action}
                        </span>
                      </td>
                      
                      <td className="px-4 py-3">
                        <SmartCell value={rule.source} label="Source Address(es)" />
                      </td>
                      <td className="px-4 py-3">
                         <div className="flex items-center gap-1.5">
                           <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" />
                           <SmartCell value={rule.destination} label="Destination Address(es)" />
                         </div>
                      </td>
                      <td className="px-4 py-3">
                         <div className="flex flex-col">
                           <SmartCell value={rule.destinationPort} label="Services / Destination Ports" />
                           {rule.service && <span className="text-[10px] text-slate-500 mt-0.5 truncate max-w-[140px] font-mono">{rule.service}</span>}
                         </div>
                      </td>
                      
                      <td className="px-4 py-3">
                        <span className="text-[11px] font-mono font-semibold text-slate-400 uppercase">
                          {rule.protocol}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                         <button className="text-slate-500 hover:text-white p-1 rounded hover:bg-slate-800 transition-colors">
                            <MoreHorizontal className="w-3.5 h-3.5" />
                         </button>
                      </td>
                    </tr>
                    
                    {isExpanded && ruleFindings.length > 0 && (
                      <tr className="bg-[#090D15]">
                        <td colSpan={9} className="px-8 py-5 border-l-2 border-cyan-400">
                          <div className="space-y-4">
                            <div className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider">
                               <AlertCircle className="w-4 h-4 text-cyan-400" />
                               <span>Security Findings on Rule #{rule.id}</span>
                            </div>
                            <div className="grid grid-cols-1 gap-3">
                              {ruleFindings.map((finding, fIdx) => (
                                <div key={fIdx} className="bg-[#0D111A] border border-slate-800 p-4 rounded-lg flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                                  <div className="space-y-1.5 flex-1">
                                    <div className="flex items-center gap-2">
                                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                                          finding.severity === 'CRITICAL' ? 'bg-rose-500/10 border-rose-500/20 text-rose-400' :
                                          finding.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/20 text-orange-400' :
                                          'bg-amber-500/10 border-amber-500/20 text-amber-400'
                                        }`}>
                                          {finding.severity}
                                        </span>
                                        <span className="text-slate-600">·</span>
                                        <span className="text-xs font-semibold text-white">{finding.category}</span>
                                        <span className="text-slate-600">·</span>
                                        <span className="text-xs text-slate-400 font-mono">Score: <strong className="text-white">{finding.score}</strong></span>
                                    </div>
                                    <p className="text-xs text-slate-300 leading-relaxed max-w-2xl">
                                        {finding.explanation}
                                    </p>
                                  </div>
                                  <div className="w-full md:w-80 bg-slate-900/60 rounded-lg p-3 border border-slate-800 shrink-0">
                                    <div className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider mb-1">
                                      Remediation
                                    </div>
                                    <p className="text-xs text-slate-300 font-sans">
                                      {finding.recommendation}
                                    </p>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              }) : (
                <tr>
                  <td colSpan={9} className="py-16 text-center text-slate-500">
                    <div className="flex flex-col items-center gap-2">
                        <FilterIcon className="w-6 h-6 text-slate-600 opacity-60" />
                        <p className="text-sm font-semibold text-slate-300">No access control rules match current filters</p>
                        <p className="text-xs text-slate-500">Clear or loosen filter conditions to inspect all rules</p>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default RuleTable;
