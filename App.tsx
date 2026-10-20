
import React, { useState, useCallback, useMemo, useEffect } from 'react';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import Uploader from './components/Uploader';
import FindingsList from './components/FindingsList';
import RuleTable from './components/RuleTable';
import Settings from './components/Settings';
import HygieneTab from './components/HygieneTab';
import FilterBar from './components/FilterBar';
import DocumentationTab from './components/DocumentationTab';
import { analyzeRules } from './engine/analyzer';
import { FirewallRule, AnalysisResults, InsecurePortSetting, InsecureServiceSetting, FilterState, FilterClause, ServiceObject, NetworkObject } from './types';
import { DEFAULT_INSECURE_PORTS } from './constants';
import { ShieldAlert, FileCheck, Search, Database } from 'lucide-react';

const STORAGE_KEY_PORTS = 'ruleguardx_port_settings';
const STORAGE_KEY_SERVICES = 'ruleguardx_service_settings';

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState('import');
  const [rawRules, setRawRules] = useState<FirewallRule[]>([]);
  const [serviceObjects, setServiceObjects] = useState<Map<string, ServiceObject>>(new Map());
  const [networkObjects, setNetworkObjects] = useState<Map<string, NetworkObject>>(new Map());
  const [filters, setFilters] = useState<FilterState>({
    clauses: [],
    quickSearch: ''
  });
  
  const [portSettings, setPortSettings] = useState<InsecurePortSetting[]>(() => {
    const saved = localStorage.getItem(STORAGE_KEY_PORTS);
    if (saved) {
      try { return JSON.parse(saved); } catch (e) { console.error(e); }
    }
    return DEFAULT_INSECURE_PORTS;
  });

  const [serviceSettings, setServiceSettings] = useState<InsecureServiceSetting[]>(() => {
    const saved = localStorage.getItem(STORAGE_KEY_SERVICES);
    if (saved) {
      try { return JSON.parse(saved); } catch (e) { console.error(e); }
    }
    return [];
  });

  const results = useMemo(() => {
    if (rawRules.length === 0) return null;
    return analyzeRules(rawRules, portSettings, serviceSettings, serviceObjects, networkObjects);
  }, [rawRules, portSettings, serviceSettings, serviceObjects, networkObjects]);

  const handleDataLoaded = (rules: FirewallRule[], services: Map<string, ServiceObject>, networks: Map<string, NetworkObject>) => {
    setRawRules(rules);
    setServiceObjects(services);
    setNetworkObjects(networks);
    setActiveTab('dashboard');
  };

  const handleSettingsSave = (newPorts: InsecurePortSetting[], newServices: InsecureServiceSetting[]) => {
    setPortSettings(newPorts);
    setServiceSettings(newServices);
    localStorage.setItem(STORAGE_KEY_PORTS, JSON.stringify(newPorts));
    localStorage.setItem(STORAGE_KEY_SERVICES, JSON.stringify(newServices));
    if (rawRules.length > 0) {
      setActiveTab('dashboard');
    }
  };

  const navigateWithFilters = (tab: string, clauses: FilterClause[]) => {
    setFilters({ quickSearch: '', clauses: clauses });
    setActiveTab(tab);
  };

  const categories = useMemo(() => {
    if (!results) return [];
    const cats = new Set<string>();
    results.findings.forEach(f => cats.add(f.category));
    return Array.from(cats);
  }, [results]);

  const renderContent = () => {
    if (activeTab === 'import') {
      return (
        <div className="space-y-12 py-10 animate-in slide-in-from-bottom duration-500">
          <div className="text-center space-y-4 max-w-2xl mx-auto">
             <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-500/10 border border-cyan-500/20 rounded-md text-cyan-400 text-xs font-semibold uppercase tracking-wider">
               <FileCheck className="w-3.5 h-3.5" /> Firewall Security Auditor
             </div>
             <h2 className="text-4xl font-extrabold text-white tracking-tight leading-tight">
               RuleGuard<span className="text-cyan-400">X</span>
             </h2>
             <p className="text-slate-400 text-sm leading-relaxed max-w-xl mx-auto">
               Client-side firewall policy auditor and risk analysis engine. Inspect access rules, dereference service & network objects, and identify exposure without false positives.
             </p>
          </div>
          <Uploader onDataLoaded={handleDataLoaded} />
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl mx-auto mt-16">
             <FeatureCard 
               icon={ShieldAlert} 
               title="Strict Port Matrix" 
               description="35+ high-risk service ports and arbitrary service object definitions evaluated against zero-trust standards."
             />
             <FeatureCard 
               icon={Search} 
               title="Dynamic Object Resolution" 
               description="Parse service and network object exports to dereference nested group members and compute exact subnet sizes."
             />
             <FeatureCard 
               icon={Database} 
               title="Correlation & Hygiene Engine" 
               description="Detect shadowed, redundant, and conflicting access-lists across large rulebases without cloud transmission."
             />
          </div>
        </div>
      );
    }

    if (activeTab === 'settings') {
      return <Settings 
        portSettings={portSettings} 
        serviceSettings={serviceSettings} 
        onSave={handleSettingsSave} 
        serviceObjectMap={serviceObjects}
      />;
    }

    if (activeTab === 'docs') {
      return <DocumentationTab />;
    }

    if (!results) return null;

    return (
      <div className="space-y-6">
        {activeTab !== 'dashboard' && activeTab !== 'hygiene' && activeTab !== 'docs' && (
          <FilterBar filters={filters} setFilters={setFilters} categories={categories} />
        )}
        
        {(() => {
          switch (activeTab) {
            case 'dashboard':
              return <Dashboard results={results} onNavigate={navigateWithFilters} />;
            case 'findings':
              return <FindingsList findings={results.findings} rules={results.rules} filters={filters} />;
            case 'hygiene':
              return <HygieneTab hygiene={results.hygiene} />;
            case 'rules':
              return <RuleTable rules={results.rules} findings={results.findings} filters={filters} />;
            default:
              return <Dashboard results={results} onNavigate={navigateWithFilters} />;
          }
        })()}
      </div>
    );
  };

  return (
    <Layout activeTab={activeTab} setActiveTab={setActiveTab} isAnalyzed={rawRules.length > 0}>
      {renderContent()}
    </Layout>
  );
};

const FeatureCard: React.FC<{ icon: any, title: string, description: string }> = ({ icon: Icon, title, description }) => (
  <div className="bg-[#0D111A] border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition-colors group">
    <div className="w-10 h-10 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center mb-4 text-cyan-400 group-hover:border-cyan-500/30 transition-colors">
      <Icon className="w-5 h-5" />
    </div>
    <h3 className="text-sm font-bold text-white mb-1.5">{title}</h3>
    <p className="text-xs text-slate-400 leading-relaxed">{description}</p>
  </div>
);

export default App;
