
import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell, PieChart, Pie, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, AreaChart, Area } from 'recharts';
import { AnalysisResults, Severity, FilterClause } from '../types';
import { AlertTriangle, ShieldCheck, Activity, Target, Network, Layers, Zap, Info, HelpCircle, ArrowUpRight, ArrowDownRight, TrendingUp } from 'lucide-react';

interface DashboardProps {
  results: AnalysisResults;
  onNavigate: (tab: string, clauses: FilterClause[]) => void;
}

const STAT_DEFINITIONS = {
  'Policy Risk Score': 'An aggregate metric representing the overall security posture.',
  'Security Findings': 'Total unique security risks identified.',
  'ANY Exposure': 'Rules that use "ANY" for Source, Destination, or Port.',
  'Critical Blocks': 'Findings that pose an immediate severe threat.'
};

const Dashboard: React.FC<DashboardProps> = ({ results, onNavigate }) => {
  const { summary, findings } = results;

  const severityData = [
    { name: 'Critical', value: summary.criticalFindings, color: '#ef4444', key: 'CRITICAL' },
    { name: 'High', value: summary.highFindings, color: '#f97316', key: 'HIGH' },
    { name: 'Medium', value: summary.mediumFindings, color: '#eab308', key: 'MEDIUM' },
    { name: 'Low', value: summary.lowFindings, color: '#3b82f6', key: 'LOW' },
  ].filter(d => d.value > 0);

  const categoryCounts: Record<string, number> = {};
  findings.forEach(f => {
    categoryCounts[f.category] = (categoryCounts[f.category] || 0) + 1;
  });

  const categoryData = Object.entries(categoryCounts)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  const outlookData = [
    { subject: 'Scope', A: findings.filter(f => f.category === 'Subnet Scope').length * 10, fullMark: 100, category: 'Subnet Scope' },
    { subject: 'Services', A: findings.filter(f => f.category === 'Insecure Port').length * 10, fullMark: 100, category: 'Insecure Port' },
    { subject: 'Lateral', A: findings.filter(f => f.category === 'Correlation Error').length * 10, fullMark: 100, category: 'Correlation Error' },
    { subject: 'Exposure', A: findings.filter(f => f.category === 'Excessive Exposure').length * 20, fullMark: 100, category: 'Excessive Exposure' },
    { subject: 'Hygiene', A: findings.filter(f => f.category === 'Policy Hygiene').length * 10, fullMark: 100, category: 'Policy Hygiene' },
  ];

  const anyFindings = findings.filter(f => f.category === 'Excessive Exposure');
  const anyStats = [
    { name: 'Src ANY', value: anyFindings.filter(f => f.explanation.toLowerCase().includes('source')).length, color: '#ef4444' },
    { name: 'Dst ANY', value: anyFindings.filter(f => f.explanation.toLowerCase().includes('destination')).length, color: '#f87171' },
    { name: 'Proto', value: anyFindings.filter(f => f.explanation.toLowerCase().includes('protocol')).length, color: '#dc2626' },
    { name: 'Port', value: anyFindings.filter(f => f.explanation.toLowerCase().includes('port')).length, color: '#991b1b' },
  ].filter(d => d.value > 0);

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      
      {/* Top Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <EnterpriseStatCard 
            title="Policy Risk Score" 
            value={summary.averageRiskScore} 
            suffix="%"
            icon={Target} 
            badge={summary.averageRiskScore > 70 ? 'CRITICAL RISK' : summary.averageRiskScore > 40 ? 'ELEVATED' : 'STABLE'}
            badgeVariant={summary.averageRiskScore > 70 ? 'danger' : summary.averageRiskScore > 40 ? 'warning' : 'success'}
            onClick={() => onNavigate('findings', [])}
            subText="Posture Index (0-100)"
            iconColor="text-rose-400"
            iconBg="bg-rose-500/10 border-rose-500/20"
        />
        <EnterpriseStatCard 
            title="Total Findings" 
            value={findings.length} 
            icon={AlertTriangle} 
            badge={`${summary.criticalFindings} Critical`}
            badgeVariant={summary.criticalFindings > 0 ? 'danger' : 'neutral'}
            onClick={() => onNavigate('findings', [])}
            subText="Flagged Rule Violations"
            iconColor="text-amber-400"
            iconBg="bg-amber-500/10 border-amber-500/20"
        />
        <EnterpriseStatCard 
            title="ANY Exposure Rules" 
            value={anyFindings.length} 
            icon={Zap} 
            badge={anyFindings.length > 0 ? 'Over-Permissive' : 'Clean'}
            badgeVariant={anyFindings.length > 0 ? 'danger' : 'success'}
            onClick={() => onNavigate('rules', [{ id: 'dash-any', field: 'category', operator: 'CONTAINS', value: 'Excessive Exposure', logicalOperator: 'AND' }])}
            subText="Unrestricted Vectors"
            iconColor="text-cyan-400"
            iconBg="bg-cyan-500/10 border-cyan-500/20"
        />
        <EnterpriseStatCard 
            title="Rules Analyzed" 
            value={summary.totalRules} 
            icon={Layers} 
            badge={`${Math.round((summary.enabledRules/summary.totalRules)*100)}% Active`}
            badgeVariant="neutral"
            onClick={() => onNavigate('rules', [])}
            subText={`${summary.enabledRules} Enabled / ${summary.totalRules - summary.enabledRules} Disabled`}
            iconColor="text-sky-400"
            iconBg="bg-sky-500/10 border-sky-500/20"
        />
      </div>

      {/* Main Charts Area */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Severity Distribution Chart */}
        <div className="lg:col-span-2 bg-[#0D111A] border border-slate-800 rounded-xl p-6">
          <div className="flex justify-between items-center mb-6">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Severity Breakdown
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Distribution of security findings by threat tier</p>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span>Real-Time Audit</span>
            </div>
          </div>
          
          <div className="h-[300px] w-full">
<<<<<<< HEAD
            <ResponsiveContainer width="100%" height="100%" minWidth={100} minHeight={100}>
              <BarChart
                data={severityData}
                layout="vertical"
                onClick={(data) => {
                  const payload = (data as { activePayload?: Array<{ payload: typeof severityData[number] }> } | null)?.activePayload?.[0]?.payload;
                  if (payload) handleSeverityBarClick(payload);
                }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={true} vertical={false} />
                <XAxis type="number" stroke="#94a3b8" hide />
                <YAxis dataKey="name" type="category" stroke="#94a3b8" width={80} tick={{ fontSize: 12 }} />
                <Tooltip 
                    cursor={{fill: '#1e293b', opacity: 0.4}}
                    contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                    itemStyle={{ color: '#f1f5f9', fontSize: '12px' }}
=======
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} barSize={36}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                <XAxis 
                  dataKey="name" 
                  stroke="#64748B" 
                  tick={{fill: '#94A3B8', fontSize: 12, fontWeight: 500}} 
                  axisLine={{stroke: '#334155'}} 
                  tickLine={false} 
>>>>>>> 73c4524 (V2.1 updates)
                />
                <YAxis 
                  stroke="#64748B" 
                  tick={{fill: '#94A3B8', fontSize: 12}} 
                  axisLine={{stroke: '#334155'}} 
                  tickLine={false} 
                />
                <Tooltip 
                  cursor={{fill: '#1E293B', opacity: 0.5}}
                  contentStyle={{ 
                    backgroundColor: '#0D111A', 
                    border: '1px solid #334155', 
                    borderRadius: '8px', 
                    padding: '8px 12px',
                    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.4)' 
                  }}
                  itemStyle={{ color: '#F1F5F9', fontWeight: 600, fontSize: '13px' }}
                  labelStyle={{ color: '#94A3B8', fontSize: '11px', marginBottom: '4px', textTransform: 'uppercase' }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Radar Chart / Posture */}
        <div className="bg-[#0D111A] border border-slate-800 rounded-xl p-6">
           <div className="mb-6">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                Security Posture Matrix
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Attack surface & policy exposure index</p>
           </div>
           <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="68%" data={outlookData}>
                <PolarGrid stroke="#243044" strokeDasharray="3 3" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: '#94A3B8', fontSize: 11, fontWeight: 600 }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                <Radar
                  name="Risk Profile"
                  dataKey="A"
                  stroke="#06B6D4"
                  strokeWidth={2}
                  fill="#06B6D4"
                  fillOpacity={0.25}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* ANY Exposure Breakdown */}
        <div className="bg-[#0D111A] border border-slate-800 rounded-xl p-6">
          <div className="flex justify-between items-start mb-6">
             <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Zap className="w-4 h-4 text-rose-400" />
                  ANY Rule Exposure Analysis
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">Permissive rule breakdown across attack vectors</p>
             </div>
             <span className="text-[10px] font-semibold text-rose-400 bg-rose-500/10 border border-rose-500/20 px-2.5 py-1 rounded">
               {anyFindings.length > 0 ? 'HIGH PRIORITY' : 'SECURE'}
             </span>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-6">
            <div className="h-[200px] w-[200px] relative shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={anyStats}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                    stroke="#0D111A"
                    strokeWidth={2}
                  >
                    {anyStats.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0D111A', border: '1px solid #334155', borderRadius: '6px' }}
                    itemStyle={{ color: '#fff', fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex items-center justify-center flex-col pointer-events-none">
                <span className="text-2xl font-bold font-mono text-white tabular-nums">{anyFindings.length}</span>
                <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">Rules</span>
              </div>
            </div>

            <div className="flex-1 grid grid-cols-2 gap-2.5 w-full">
               {anyStats.map((stat, i) => (
                 <div key={i} className="bg-slate-900/70 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                       <div className="w-2 h-2 rounded-xs" style={{backgroundColor: stat.color}} />
                       <span className="text-xs font-medium text-slate-300">{stat.name}</span>
                    </div>
                    <span className="text-sm font-bold font-mono text-white tabular-nums">{stat.value}</span>
                 </div>
               ))}
            </div>
          </div>
        </div>

        {/* Compliance Baseline */}
        <div className="bg-[#0D111A] border border-slate-800 rounded-xl p-6 flex flex-col">
          <div className="mb-5">
             <h3 className="text-base font-bold text-white flex items-center gap-2">
               <ShieldCheck className="w-4 h-4 text-emerald-400" />
               Compliance Framework Baseline
             </h3>
             <p className="text-xs text-slate-400 mt-0.5">Adherence to NIST SP 800-41 and CIS Control 12 standards</p>
          </div>

          <div className="flex-1 space-y-2.5">
            <ComplianceRow 
              label="Least Privilege Access" 
              status={summary.criticalFindings > 0 ? 'Fail' : 'Pass'} 
              desc="Evaluates broad wildcard permissions and unsegmented ports."
            />
            <ComplianceRow 
              label="Network Zone Segmentation" 
              status={findings.filter(f => f.category === 'Subnet Scope' && f.severity === 'CRITICAL').length > 5 ? 'Warn' : 'Pass'} 
              desc="Verifies that large subnets (/16 or larger) are properly constrained."
            />
            <ComplianceRow 
              label="Policy Hygiene & Order" 
              status={findings.filter(f => f.category === 'Policy Hygiene').length > (results.rules.length * 0.2) ? 'Fail' : 'Pass'} 
              desc="Audits shadowed and redundant rules against technical debt thresholds."
            />
            <ComplianceRow 
              label="Zero Trust Architecture" 
              status={anyFindings.length > 0 ? 'Fail' : 'Pass'} 
              desc="Checks for absence of open source/destination/port ANY definitions."
            />
          </div>
        </div>
      </div>
    </div>
  );
};

const EnterpriseStatCard = ({ 
  title, 
  value, 
  suffix = '', 
  icon: Icon, 
  badge, 
  badgeVariant = 'neutral', 
  onClick, 
  subText,
  iconColor,
  iconBg
}: any) => {
  const getBadgeStyle = () => {
    switch (badgeVariant) {
      case 'danger': return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      case 'warning': return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'success': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      default: return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <button 
      onClick={onClick}
      className="bg-[#0D111A] border border-slate-800 rounded-xl p-5 text-left transition-all hover:border-slate-700 hover:bg-[#101622] group"
    >
      <div className="flex justify-between items-center mb-3">
        <div className={`p-2 rounded-lg border ${iconBg} ${iconColor}`}>
          <Icon className="w-4 h-4" />
        </div>
        {badge && (
          <span className={`text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded border ${getBadgeStyle()}`}>
            {badge}
          </span>
        )}
      </div>
      
      <div>
        <div className="text-2xl font-bold font-mono tracking-tight text-white tabular-nums">
          {value}<span className="text-sm font-sans text-slate-400 font-normal ml-0.5">{suffix}</span>
        </div>
        <p className="text-xs font-semibold text-slate-200 mt-1">{title}</p>
        <p className="text-[11px] text-slate-400 mt-0.5">{subText}</p>
      </div>
    </button>
  );
};

const ComplianceRow = ({ label, status, desc }: any) => (
  <div className="flex items-center justify-between p-3 bg-slate-900/60 border border-slate-800/80 rounded-lg hover:border-slate-700/80 transition-colors">
    <div className="flex flex-col pr-3">
       <span className="text-xs font-semibold text-slate-200">{label}</span>
       <span className="text-[11px] text-slate-400 mt-0.5">{desc}</span>
    </div>
    <span className={`px-2.5 py-1 rounded text-[11px] font-bold uppercase tracking-wider shrink-0 ${
      status === 'Pass' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 
      status === 'Warn' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 
      'bg-rose-500/10 text-rose-400 border border-rose-500/20'
    }`}>
      {status}
    </span>
  </div>
);

export default Dashboard;
