
import React from 'react';
import { AnalysisFinding, FilterState, FilterClause, FirewallRule } from '../types';
import { SEVERITY_COLORS } from '../constants';
import { AlertCircle, Download, Filter, Target, ArrowRight, ChevronRight, ShieldAlert } from 'lucide-react';

interface FindingsListProps {
  findings: AnalysisFinding[];
  rules: FirewallRule[];
  filters: FilterState;
}

const FindingsList: React.FC<FindingsListProps> = ({ findings, rules, filters }) => {
  const evaluateClause = (f: AnalysisFinding, clause: FilterClause): boolean => {
    let targetValue: string = '';
    const associatedRule = rules.find(r => r.id === f.ruleId);
    
    if (clause.field === 'id') targetValue = f.ruleId;
    else if (clause.field === 'name') targetValue = f.ruleName;
    else if (clause.field === 'severity') targetValue = f.severity;
    else if (clause.field === 'category') targetValue = f.category;
    else if (clause.field === 'description') targetValue = f.explanation;
    else if (clause.field === 'source') targetValue = associatedRule?.source || '';
    else if (clause.field === 'destination') targetValue = associatedRule?.destination || '';
    else if (clause.field === 'destinationPort') targetValue = associatedRule?.destinationPort || '';
    else if (clause.field === 'protocol') targetValue = associatedRule?.protocol || '';
    else if (clause.field === 'action') targetValue = associatedRule?.action || '';
    else return true;

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

  const filtered = findings.filter(f => {
    const quickSearchMatch = !filters.quickSearch || [
      f.explanation, f.ruleName, f.ruleId, f.category, f.severity
    ].some(field => String(field).toLowerCase().includes(filters.quickSearch.toLowerCase()));

    if (!quickSearchMatch) return false;
    if (filters.clauses.length === 0) return true;

    let result = evaluateClause(f, filters.clauses[0]);
    for (let i = 1; i < filters.clauses.length; i++) {
      const clause = filters.clauses[i];
      const clauseResult = evaluateClause(f, clause);
      if (clause.logicalOperator === 'AND') result = result && clauseResult;
      else result = result || clauseResult;
    }
    return result;
  }).sort((a, b) => b.score - a.score);

  const getTriggerLabel = (finding: AnalysisFinding) => {
    const text = finding.explanation;
    if (finding.category === 'Insecure Port') {
      const match = text.match(/Port (\d+)/i);
      return match ? `PORT ${match[1]}` : 'INSECURE PORT';
    }
    if (finding.category === 'Subnet Scope') {
      const match = text.match(/\/\d+/);
      return match ? `SUBNET ${match[0]}` : 'LARGE SCOPE';
    }
    if (finding.category === 'Insecure Service Object' || text.includes('service object')) {
      const match = text.match(/'([^']+)'/);
      return match ? `OBJECT: ${match[1].toUpperCase()}` : 'INSECURE OBJECT';
    }
    if (finding.category === 'Excessive Exposure') {
      if (text.toLowerCase().includes('port')) return 'ANY PORT';
      if (text.toLowerCase().includes('source')) return 'ANY SOURCE';
      if (text.toLowerCase().includes('destination')) return 'ANY DEST';
      return 'ANY EXPOSURE';
    }
    return finding.category.toUpperCase();
  };

  const downloadReport = () => {
    const data = JSON.stringify(findings, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'firewall_findings.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h3 className="text-lg font-bold text-white tracking-tight">Security Vulnerability Findings</h3>
          <p className="text-slate-400 text-xs mt-0.5">
            Displaying <span className="font-mono text-cyan-400 font-bold tabular-nums">{filtered.length}</span> security events matching filter criteria
          </p>
        </div>
        <button 
          onClick={downloadReport}
          className="inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors shadow-xs self-start sm:self-auto"
        >
          <Download className="w-3.5 h-3.5 text-cyan-400" /> Export JSON
        </button>
      </div>

      <div className="space-y-3">
        {filtered.length > 0 ? filtered.map((finding, idx) => {
          const sevColor = 
            finding.severity === 'CRITICAL' ? 'border-l-rose-500' :
            finding.severity === 'HIGH' ? 'border-l-orange-500' :
            finding.severity === 'MEDIUM' ? 'border-l-amber-500' : 'border-l-sky-500';

          const sevBadge = 
            finding.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' :
            finding.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
            finding.severity === 'MEDIUM' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
            'bg-sky-500/10 text-sky-400 border-sky-500/20';

          return (
            <div 
              key={`${finding.ruleId}-${idx}`} 
              className={`bg-[#0D111A] border border-slate-800 hover:border-slate-700 rounded-xl p-5 transition-colors border-l-4 ${sevColor}`}
            >
              <div className="flex flex-col lg:flex-row gap-5 justify-between">
                <div className="flex-1 space-y-2.5">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${sevBadge}`}>
                      {finding.severity}
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-300 font-semibold">{finding.category}</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-400 font-mono text-[11px]">Score: <strong className="text-white tabular-nums">{finding.score}</strong></span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-400 font-mono text-[11px]">Rule #{finding.ruleId}</span>
                  </div>
                  
                  <div>
                    <h4 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                      {finding.ruleName}
                    </h4>
                    <p className="text-slate-300 text-sm mt-1.5 leading-relaxed">
                      {finding.explanation}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 pt-1">
                    <div className="px-2 py-1 bg-slate-900 border border-slate-800 rounded text-[11px] font-mono text-cyan-400 flex items-center gap-1.5">
                      <Target className="w-3 h-3 text-cyan-400" />
                      <span>Vector: {getTriggerLabel(finding)}</span>
                    </div>
                  </div>
                </div>

                <div className="lg:w-80 bg-slate-900/60 border border-slate-800/80 rounded-lg p-3.5 flex flex-col justify-center shrink-0">
                  <div className="flex items-center gap-1.5 text-slate-300 text-xs font-semibold uppercase tracking-wider mb-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Recommended Remediation</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans">
                    {finding.recommendation}
                  </p>
                </div>
              </div>
            </div>
          );
        }) : (
          <div className="flex flex-col items-center justify-center p-16 text-slate-500 bg-[#0D111A] border border-dashed border-slate-800 rounded-xl">
            <div className="p-3 bg-slate-900 rounded-lg mb-3">
              <Filter className="w-6 h-6 text-slate-600" />
            </div>
            <p className="text-sm font-semibold text-slate-300">No findings match the current filter criteria</p>
            <p className="text-xs text-slate-500 mt-1">Adjust or clear filters to view additional security events</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default FindingsList;
