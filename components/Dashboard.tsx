
import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell, PieChart, Pie, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts';
import { AnalysisResults, Severity, FilterClause } from '../types';
import { AlertTriangle, ShieldCheck, Activity, Target, Network, Layers, Zap, Info, HelpCircle } from 'lucide-react';

interface DashboardProps {
  results: AnalysisResults;
  onNavigate: (tab: string, clauses: FilterClause[]) => void;
}

const STAT_DEFINITIONS = {
  'Policy Risk Score': 'An aggregate metric representing the overall security posture. Higher scores indicate multiple critical exposures or non-compliant rule patterns.',
  'Security Findings': 'The total number of unique security risks identified across the policy set, categorized by severity from Informational to Critical.',
  'ANY Exposure': 'Rules that use "ANY" for Source, Destination, or Port. This effectively bypasses firewall filtering and is a major security risk.',
  'Critical Blocks': 'The subset of security findings that pose an immediate and severe threat to the network, such as exposed administrative ports (RDP/SSH).'
};

const COMPLIANCE_DEFINITIONS = {
  'Least Privilege': 'The security principle of restricting access rights for users, accounts, and processes to only those resources which are absolutely necessary to perform authorized activities.',
  'Network Segmentation': 'The architectural practice of splitting a network into smaller, isolated sections to limit the blast radius of a potential breach and control lateral movement.',
  'Policy Hygiene': 'The process of maintaining a clean, performant, and understandable rule set by eliminating technical debt such as shadowed, redundant, or unused rules.',
  'Zero Trust Baseline': 'A strategic security framework that requires all users and devices, whether in or out of the network, to be authenticated and authorized before being granted access.'
};

const Dashboard: React.FC<DashboardProps> = ({ results, onNavigate }) => {
  const { summary, findings } = results;

  const severityData = [
    { name: 'Critical', value: summary.criticalFindings, color: '#dc2626', key: 'CRITICAL' },
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
    { subject: 'Broad Scope', A: findings.filter(f => f.category === 'Subnet Scope').length * 10, fullMark: 100, category: 'Subnet Scope' },
    { subject: 'Services', A: findings.filter(f => f.category === 'Insecure Port').length * 10, fullMark: 100, category: 'Insecure Port' },
    { subject: 'Lateral Mov.', A: findings.filter(f => f.category === 'Correlation Error').length * 10, fullMark: 100, category: 'Correlation Error' },
    { subject: 'ANY/ANY', A: findings.filter(f => f.category === 'Excessive Exposure').length * 20, fullMark: 100, category: 'Excessive Exposure' },
    { subject: 'Hygiene', A: findings.filter(f => f.category === 'Policy Hygiene').length * 10, fullMark: 100, category: 'Policy Hygiene' },
  ];

  const anyFindings = findings.filter(f => f.category === 'Excessive Exposure');
  const anyStats = [
    { name: 'Source ANY', value: anyFindings.filter(f => f.explanation.toLowerCase().includes('source')).length, color: '#ef4444', search: 'source' },
    { name: 'Dest ANY', value: anyFindings.filter(f => f.explanation.toLowerCase().includes('destination')).length, color: '#f87171', search: 'destination' },
    { name: 'Proto ANY', value: anyFindings.filter(f => f.explanation.toLowerCase().includes('protocol')).length, color: '#dc2626', search: 'protocol' },
    { name: 'Port ANY', value: anyFindings.filter(f => f.explanation.toLowerCase().includes('port')).length, color: '#991b1b', search: 'port' },
  ].filter(d => d.value > 0);

  const anySeverityStats = [
    { severity: 'CRITICAL', count: anyFindings.filter(f => f.severity === 'CRITICAL').length, color: 'text-red-600', key: 'CRITICAL' },
    { severity: 'HIGH', count: anyFindings.filter(f => f.severity === 'HIGH').length, color: 'text-orange-500', key: 'HIGH' },
    { severity: 'MEDIUM', count: anyFindings.filter(f => f.severity === 'MEDIUM').length, color: 'text-yellow-500', key: 'MEDIUM' },
  ].filter(s => s.count > 0);

  const handleSeverityBarClick = (data: any) => {
    onNavigate('findings', [{
      id: 'dash-sev',
      field: 'severity',
      operator: 'EQUALS',
      value: data.key,
      logicalOperator: 'AND'
    }]);
  };

  const handleRadarClick = (data: any) => {
    if (data && data.activePayload && data.activePayload[0]) {
      const cat = data.activePayload[0].payload.category;
      onNavigate('findings', [{
        id: 'dash-cat',
        field: 'category',
        operator: 'EQUALS',
        value: cat,
        logicalOperator: 'AND'
      }]);
    }
  };

  const handlePieClick = (data: any) => {
    onNavigate('rules', [
      { id: 'dash-any-cat', field: 'category', operator: 'CONTAINS', value: 'Excessive Exposure', logicalOperator: 'AND' },
      { id: 'dash-any-spec', field: 'description', operator: 'CONTAINS', value: data.search, logicalOperator: 'AND' }
    ]);
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard 
            title="Policy Risk Score" 
            value={`${summary.averageRiskScore}%`} 
            icon={Target} 
            color="text-indigo-400"
            trend={summary.averageRiskScore > 70 ? 'CRITICAL' : summary.averageRiskScore > 40 ? 'ELEVATED' : 'STABLE'}
            onClick={() => onNavigate('findings', [])}
            description={STAT_DEFINITIONS['Policy Risk Score']}
        />
        <StatCard 
            title="Security Findings" 
            value={findings.length} 
            icon={AlertTriangle} 
            color="text-orange-400"
            onClick={() => onNavigate('findings', [])}
            description={STAT_DEFINITIONS['Security Findings']}
        />
        <StatCard 
            title="ANY Exposure" 
            value={anyFindings.length} 
            icon={Zap} 
            color="text-red-500"
            trend={anyFindings.length > 0 ? 'CRITICAL' : 'SAFE'}
            onClick={() => onNavigate('rules', [{ id: 'dash-any', field: 'category', operator: 'CONTAINS', value: 'Excessive Exposure', logicalOperator: 'AND' }])}
            description={STAT_DEFINITIONS['ANY Exposure']}
        />
        <StatCard 
            title="Critical Blocks" 
            value={summary.criticalFindings} 
            icon={ShieldCheck} 
            color="text-red-500"
            onClick={() => onNavigate('findings', [{ id: 'dash-crit', field: 'severity', operator: 'EQUALS', value: 'CRITICAL', logicalOperator: 'AND' }])}
            description={STAT_DEFINITIONS['Critical Blocks']}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900/50 border border-slate-800 p-6 rounded-xl overflow-hidden min-h-[400px]">
          <h3 className="text-lg font-semibold mb-6 flex items-center gap-2">
            <Activity className="w-5 h-5 text-indigo-400" />
            Overall Risk Severity Breakdown (Click Bars to Filter)
          </h3>
          <div className="h-[300px] w-full">
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
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={30} className="cursor-pointer">
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-slate-900/50 border border-slate-800 p-6 rounded-xl overflow-hidden min-h-[400px]">
          <h3 className="text-lg font-semibold mb-6 flex items-center gap-2">
            <Network className="w-5 h-5 text-indigo-400" />
            Security Posture Outlook (Click Radar)
          </h3>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%" minWidth={100} minHeight={100}>
              <RadarChart cx="50%" cy="50%" outerRadius="80%" data={outlookData} onClick={handleRadarClick}>
                <PolarGrid stroke="#334155" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                <Radar
                  name="Risk Profile"
                  dataKey="A"
                  stroke="#6366f1"
                  fill="#6366f1"
                  fillOpacity={0.6}
                  className="cursor-pointer"
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900/50 border border-slate-800 p-6 rounded-xl relative overflow-hidden min-h-[350px]">
          <div className="absolute top-0 right-0 p-4 opacity-10">
            <AlertTriangle className="w-32 h-32 text-red-500" />
          </div>
          <div className="flex items-center justify-between mb-8">
            <h3 className="text-xl font-black flex items-center gap-2">
              <Zap className="w-6 h-6 text-red-500" />
              'ANY' Rule Severity & Factor Density
            </h3>
            <div className="bg-red-500/10 border border-red-500/20 px-3 py-1 rounded-full flex items-center gap-2">
               <span className="text-[10px] font-black text-red-400 uppercase tracking-widest">Urgent Review</span>
            </div>
          </div>
          
          {anyFindings.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 relative z-10">
              <div className="space-y-6">
                <div className="h-[200px] w-full">
                  <ResponsiveContainer width="100%" height="100%" minWidth={100} minHeight={100}>
                    <PieChart>
                      <Pie
                        data={anyStats}
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={75}
                        paddingAngle={5}
                        dataKey="value"
                        className="cursor-pointer"
                        onClick={(data) => handlePieClick(data.payload)}
                      >
                        {anyStats.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {anyStats.map((stat, i) => (
                    <button 
                      key={i} 
                      onClick={() => handlePieClick(stat)}
                      className="bg-slate-950/40 p-2 rounded border border-slate-800 flex justify-between items-center hover:bg-slate-800 transition-colors"
                    >
                       <div className="flex items-center gap-1.5">
                          <div className="w-1.5 h-1.5 rounded-full" style={{backgroundColor: stat.color}} />
                          <span className="text-[10px] font-bold text-slate-400 uppercase tracking-tighter">{stat.name}</span>
                       </div>
                       <span className="text-xs font-black">{stat.value}</span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-4">
                <p className="text-xs font-bold text-slate-500 uppercase tracking-widest border-b border-slate-800 pb-2">Severity Distribution</p>
                <div className="space-y-3">
                  {anySeverityStats.map((s, i) => (
                    <button 
                      key={i} 
                      className="w-full flex flex-col gap-1 text-left group"
                      onClick={() => onNavigate('rules', [
                        { id: 'dash-any-c', field: 'category', operator: 'CONTAINS', value: 'Excessive Exposure', logicalOperator: 'AND' },
                        { id: 'dash-any-s', field: 'severity', operator: 'EQUALS', value: s.key, logicalOperator: 'AND' }
                      ])}
                    >
                      <div className="flex justify-between items-center text-xs">
                        <span className={`font-black tracking-tight ${s.color} group-hover:underline`}>{s.severity}</span>
                        <span className="font-mono text-slate-400">{s.count} rules</span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div 
                           className={`h-full ${s.severity === 'CRITICAL' ? 'bg-red-600' : s.severity === 'HIGH' ? 'bg-orange-500' : 'bg-yellow-500'}`}
                           style={{ width: `${(s.count / anyFindings.length) * 100}%` }}
                        />
                      </div>
                    </button>
                  ))}
                </div>
                <div className="mt-6 p-4 bg-red-900/10 border border-red-900/20 rounded-lg">
                   <div className="flex items-start gap-2">
                     <Info className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                     <p className="text-[10px] text-red-200/70 leading-relaxed italic">
                        ANY/ANY/ANY rules are evaluated as a direct compromise path. These rules effectively neutralize firewall efficacy for the targeted segment.
                     </p>
                   </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-[250px] flex flex-col items-center justify-center text-slate-600 italic">
               <ShieldCheck className="w-16 h-16 mb-4 opacity-10" />
               <p className="text-sm font-medium">Zero 'ANY' rules detected in this policy set.</p>
               <p className="text-[10px] uppercase tracking-widest mt-1">Excellent Policy Discipline</p>
            </div>
          )}
        </div>

        <div className="bg-slate-900/50 border border-slate-800 p-6 rounded-xl">
          <h3 className="text-lg font-semibold mb-4">Compliance Readiness Baseline</h3>
          <div className="grid grid-cols-2 gap-4">
            <ComplianceItem 
              label="Least Privilege" 
              status={summary.criticalFindings > 0 ? 'FAIL' : 'PASS'} 
              onClick={() => onNavigate('findings', [{ id: 'dash-lp', field: 'severity', operator: 'EQUALS', value: 'CRITICAL', logicalOperator: 'AND' }])}
              description={COMPLIANCE_DEFINITIONS['Least Privilege']}
            />
            <ComplianceItem 
              label="Network Segmentation" 
              status={findings.filter(f => f.category === 'Subnet Scope' && f.severity === 'CRITICAL').length > 5 ? 'WARNING' : 'PASS'} 
              onClick={() => onNavigate('findings', [{ id: 'dash-seg', field: 'category', operator: 'EQUALS', value: 'Subnet Scope', logicalOperator: 'AND' }])}
              description={COMPLIANCE_DEFINITIONS['Network Segmentation']}
            />
            <ComplianceItem 
              label="Policy Hygiene" 
              status={findings.filter(f => f.category === 'Policy Hygiene').length > (results.rules.length * 0.2) ? 'FAIL' : 'PASS'} 
              onClick={() => onNavigate('hygiene', [])}
              description={COMPLIANCE_DEFINITIONS['Policy Hygiene']}
            />
            <ComplianceItem 
              label="Zero Trust Baseline" 
              status={anyFindings.length > 0 ? 'FAIL' : 'PASS'} 
              onClick={() => onNavigate('rules', [{ id: 'dash-zt', field: 'category', operator: 'CONTAINS', value: 'Excessive Exposure', logicalOperator: 'AND' }])}
              description={COMPLIANCE_DEFINITIONS['Zero Trust Baseline']}
            />
          </div>
          <div className="mt-6 p-4 bg-slate-950/50 rounded-lg border border-slate-800">
             <h4 className="text-xs font-black text-slate-500 uppercase mb-2 tracking-widest flex items-center gap-2">
               Top Risks by Category <HelpCircle className="w-3 h-3 opacity-50" />
             </h4>
             <div className="space-y-2">
               {categoryData.slice(0, 3).map((cat, i) => (
                 <button 
                   key={i} 
                   className="w-full flex items-center justify-between text-xs hover:bg-slate-800 p-1 rounded transition-colors group"
                   onClick={() => onNavigate('findings', [{ id: `dash-cat-${i}`, field: 'category', operator: 'EQUALS', value: cat.name, logicalOperator: 'AND' }])}
                 >
                    <span className="text-slate-400 group-hover:text-white">{cat.name}</span>
                    <span className="font-bold text-indigo-400">{cat.value} items</span>
                 </button>
               ))}
             </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const ComplianceItem = ({ label, status, onClick, description }: { label: string, status: 'PASS' | 'FAIL' | 'WARNING', onClick: () => void, description: string }) => (
  <div className="relative group/item">
    <button 
      onClick={onClick}
      className="w-full p-3 bg-slate-950/50 border border-slate-800 rounded-lg flex flex-col gap-1 text-left hover:border-slate-600 transition-all active:scale-95"
    >
      <div className="flex items-center justify-between w-full">
        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-tighter">{label}</span>
        <Info className="w-3 h-3 text-slate-600 group-hover/item:text-indigo-400 transition-colors" />
      </div>
      <span className={`text-xs font-black ${status === 'PASS' ? 'text-green-500' : status === 'FAIL' ? 'text-red-500' : 'text-yellow-500'}`}>{status}</span>
    </button>
    
    <div className="absolute bottom-full left-0 mb-2 w-64 bg-slate-950 border border-slate-800 p-3 rounded-lg shadow-2xl opacity-0 translate-y-2 pointer-events-none group-hover/item:opacity-100 group-hover/item:translate-y-0 transition-all z-20">
      <p className="text-[11px] text-slate-300 leading-relaxed font-medium">
        <span className="text-indigo-400 font-bold uppercase block mb-1">{label}</span>
        {description}
      </p>
      <div className="absolute top-full left-6 w-2 h-2 bg-slate-950 border-r border-b border-slate-800 rotate-45 -translate-y-1" />
    </div>
  </div>
);

interface StatCardProps {
  title: string;
  value: string | number;
  icon: any;
  color: string;
  trend?: string;
  onClick?: () => void;
  description?: string;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, icon: Icon, color, trend, onClick, description }) => (
  <div className="relative group/stat">
    <button 
      onClick={onClick}
      className="bg-slate-900/50 border border-slate-800 p-5 rounded-xl hover:border-indigo-500 transition-all hover:scale-[1.02] text-left w-full group shadow-lg flex flex-col justify-between h-full"
    >
      <div className="flex justify-between items-start mb-2">
        <div className="flex items-center gap-1.5">
          <span className="text-slate-400 text-xs font-black uppercase tracking-widest group-hover:text-indigo-300">{title}</span>
          {description && <HelpCircle className="w-3 h-3 text-slate-600 group-hover:text-indigo-400 opacity-0 group-hover:opacity-100 transition-all" />}
        </div>
        <Icon className={`w-5 h-5 ${color} group-hover:scale-110 transition-transform`} />
      </div>
      <div className="flex items-baseline gap-2">
          <span className="text-3xl font-bold tracking-tight">{value}</span>
          {trend && <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${trend === 'CRITICAL' ? 'bg-red-500/10 text-red-500' : 'bg-indigo-500/10 text-indigo-500'}`}>{trend}</span>}
      </div>
    </button>

    {description && (
      <div className="absolute bottom-full left-0 mb-2 w-64 bg-slate-950 border border-slate-800 p-3 rounded-lg shadow-2xl opacity-0 translate-y-2 pointer-events-none group-hover/stat:opacity-100 group-hover/stat:translate-y-0 transition-all z-20 border-t-indigo-500 border-t-2">
        <p className="text-[10px] text-slate-400 uppercase font-black mb-1 tracking-widest">{title}</p>
        <p className="text-[11px] text-slate-200 leading-relaxed font-medium">{description}</p>
        <div className="absolute top-full left-6 w-2 h-2 bg-slate-950 border-r border-b border-slate-800 rotate-45 -translate-y-1" />
      </div>
    )}
  </div>
);

export default Dashboard;
