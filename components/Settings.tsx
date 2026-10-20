
import React, { useState, useEffect, useMemo } from 'react';
import { InsecurePortSetting, InsecureServiceSetting, Severity, ServiceObject } from '../types';
import { Save, Plus, Trash2, CheckCircle2, Box, Hash, AlertTriangle, Search } from 'lucide-react';

interface SettingsProps {
  portSettings: InsecurePortSetting[];
  serviceSettings: InsecureServiceSetting[];
  onSave: (ports: InsecurePortSetting[], services: InsecureServiceSetting[]) => void;
  serviceObjectMap?: Map<string, ServiceObject>;
}

const Settings: React.FC<SettingsProps> = ({ portSettings, serviceSettings, onSave, serviceObjectMap = new Map() }) => {
  const [currentPorts, setCurrentPorts] = useState<InsecurePortSetting[]>(portSettings);
  const [currentServices, setCurrentServices] = useState<InsecureServiceSetting[]>(serviceSettings);
  
  const [newPort, setNewPort] = useState({ port: '', label: '', criticality: 'MEDIUM' as Severity });
  const [newService, setNewService] = useState({ name: '', criticality: 'MEDIUM' as Severity });
  
  const [showSavedToast, setShowSavedToast] = useState(false);

  useEffect(() => {
    setCurrentPorts(portSettings);
    setCurrentServices(serviceSettings);
  }, [portSettings, serviceSettings]);

  // Identify insecure objects from the current active map
  const discoveredInsecureObjects = useMemo(() => {
    const list: InsecureServiceSetting[] = [];
    const insecurePortSet = new Set(currentPorts.filter(p => p.enabled).map(p => p.port));

    serviceObjectMap.forEach((obj, name) => {
      // If object not already in user's explicit service settings
      if (currentServices.some(s => s.name.toLowerCase() === name.toLowerCase())) return;

      const hasInsecurePort = obj.ports.some(p => typeof p === 'number' && insecurePortSet.has(p));
      if (hasInsecurePort) {
        list.push({
          name: obj.name,
          criticality: 'HIGH', // Automatically flag as high
          enabled: true
        });
      }
    });
    return list;
  }, [serviceObjectMap, currentPorts, currentServices]);

  const togglePort = (port: number) => {
    setCurrentPorts(prev => prev.map(s => s.port === port ? { ...s, enabled: !s.enabled } : s));
  };

  const toggleService = (name: string) => {
    setCurrentServices(prev => prev.map(s => s.name === name ? { ...s, enabled: !s.enabled } : s));
  };

  const addCustomPort = () => {
    const p = parseInt(newPort.port);
    if (isNaN(p) || !newPort.label) return;
    if (currentPorts.some(s => s.port === p)) return;
    const newItem: InsecurePortSetting = {
      port: p,
      label: newPort.label,
      criticality: newPort.criticality,
      whyInsecure: 'User-defined custom risk',
      enabled: true
    };
    setCurrentPorts([...currentPorts, newItem]);
    setNewPort({ port: '', label: '', criticality: 'MEDIUM' });
  };

  const addCustomService = (customName?: string) => {
    const nameToUse = customName || newService.name;
    if (!nameToUse) return;
    if (currentServices.some(s => s.name.toLowerCase() === nameToUse.toLowerCase())) return;
    const newItem: InsecureServiceSetting = {
      name: nameToUse,
      criticality: customName ? 'HIGH' : newService.criticality,
      enabled: true
    };
    setCurrentServices([...currentServices, newItem]);
    if (!customName) setNewService({ name: '', criticality: 'MEDIUM' });
  };

  const removePort = (port: number) => {
    setCurrentPorts(prev => prev.filter(s => s.port !== port));
  };

  const removeService = (name: string) => {
    setCurrentServices(prev => prev.filter(s => s.name !== name));
  };

  const handleApply = () => {
    onSave(currentPorts, currentServices);
    setShowSavedToast(true);
    setTimeout(() => setShowSavedToast(false), 3000);
  };

  return (
    <div className="space-y-6 pb-16">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight">Audit Engine Configuration</h2>
          <p className="text-slate-400 text-xs mt-0.5">Custom port severity definitions and flagged service object registry</p>
        </div>
        <div className="flex items-center gap-3">
          {showSavedToast && (
            <span className="text-emerald-400 text-xs font-semibold flex items-center gap-1.5 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded">
              <CheckCircle2 className="w-3.5 h-3.5" /> Saved & Applied
            </span>
          )}
          <button 
            onClick={handleApply}
            className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors shadow-xs"
          >
            <Save className="w-3.5 h-3.5" /> Apply Configuration
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          
          {/* DISCOVERED OBJECTS (ONLY SHOW IF ANY FOUND) */}
          {discoveredInsecureObjects.length > 0 && (
            <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl overflow-hidden">
              <div className="p-3.5 bg-amber-500/10 border-b border-amber-500/20 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Search className="w-4 h-4 text-amber-400" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400">Discovered Insecure Service Objects</h3>
                </div>
                <span className="text-[10px] font-bold bg-amber-500/20 text-amber-400 px-2 py-0.5 rounded">Action Recommended</span>
              </div>
              <div className="p-4 space-y-3">
                <p className="text-xs text-slate-300">
                  The following objects defined in your uploaded CSV include ports identified in your risk matrix. Add them to your permanent Insecure Services list to audit them consistently across policies.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {discoveredInsecureObjects.map(obj => (
                    <div key={obj.name} className="flex items-center justify-between bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                      <div className="flex flex-col">
                        <span className="text-xs font-semibold text-slate-200">{obj.name}</span>
                        <span className="text-[10px] text-slate-500 font-mono">Mapped Object</span>
                      </div>
                      <button 
                        onClick={() => addCustomService(obj.name)}
                        className="text-[10px] font-bold text-cyan-400 hover:text-cyan-300 uppercase px-2.5 py-1 rounded bg-cyan-500/10 border border-cyan-500/20 transition-colors"
                      >
                        Track Service
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* PORTS SECTION */}
          <div className="bg-[#0D111A] border border-slate-800 rounded-xl overflow-hidden flex flex-col shadow-xs">
            <div className="p-4 bg-[#101622] border-b border-slate-800 flex items-center gap-2">
              <Hash className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Insecure Ports Matrix</h3>
            </div>
            <div className="overflow-y-auto max-h-[380px] custom-scrollbar">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] font-semibold tracking-wider sticky top-0 z-10 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3 w-12 text-center">Active</th>
                    <th className="px-4 py-3">Port</th>
                    <th className="px-4 py-3">Service</th>
                    <th className="px-4 py-3">Threat Tier</th>
                    <th className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {currentPorts.map((s) => (
                    <tr key={s.port} className={`hover:bg-slate-800/30 transition-colors ${!s.enabled ? 'opacity-40' : ''}`}>
                      <td className="px-4 py-2.5 text-center">
                        <input 
                          type="checkbox" 
                          checked={s.enabled} 
                          onChange={() => togglePort(s.port)} 
                          className="w-3.5 h-3.5 accent-cyan-500 bg-slate-900 border-slate-700 rounded cursor-pointer" 
                        />
                      </td>
                      <td className="px-4 py-2.5 font-mono font-bold text-slate-200 tabular-nums">{s.port}</td>
                      <td className="px-4 py-2.5 text-slate-300 font-medium">{s.label}</td>
                      <td className="px-4 py-2.5">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                          s.criticality === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 
                          s.criticality === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' : 
                          'bg-amber-500/10 text-amber-400 border-amber-500/20'
                        }`}>
                          {s.criticality}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <button 
                          onClick={() => removePort(s.port)} 
                          className="text-slate-500 hover:text-rose-400 p-1 rounded hover:bg-rose-500/10 transition-colors"
                          title="Remove port rule"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* SERVICES SECTION */}
          <div className="bg-[#0D111A] border border-slate-800 rounded-xl overflow-hidden flex flex-col shadow-xs">
            <div className="p-4 bg-[#101622] border-b border-slate-800 flex items-center gap-2">
              <Box className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Insecure Service Objects Registry</h3>
            </div>
            <div className="overflow-y-auto max-h-[380px] custom-scrollbar">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] font-semibold tracking-wider sticky top-0 z-10 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3 w-12 text-center">Active</th>
                    <th className="px-4 py-3">Object Identifier</th>
                    <th className="px-4 py-3">Threat Tier</th>
                    <th className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {currentServices.length > 0 ? currentServices.map((s) => (
                    <tr key={s.name} className={`hover:bg-slate-800/30 transition-colors ${!s.enabled ? 'opacity-40' : ''}`}>
                      <td className="px-4 py-2.5 text-center">
                        <input 
                          type="checkbox" 
                          checked={s.enabled} 
                          onChange={() => toggleService(s.name)} 
                          className="w-3.5 h-3.5 accent-cyan-500 bg-slate-900 border-slate-700 rounded cursor-pointer" 
                        />
                      </td>
                      <td className="px-4 py-2.5 font-mono font-medium text-slate-200">{s.name}</td>
                      <td className="px-4 py-2.5">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                          s.criticality === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 
                          s.criticality === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' : 
                          'bg-amber-500/10 text-amber-400 border-amber-500/20'
                        }`}>
                          {s.criticality}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <button 
                          onClick={() => removeService(s.name)} 
                          className="text-slate-500 hover:text-rose-400 p-1 rounded hover:bg-rose-500/10 transition-colors"
                          title="Remove service"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  )) : (
                    <tr>
                      <td colSpan={4} className="px-4 py-8 text-center text-slate-500 text-xs">
                        No custom service objects registered yet. Add definitions below or acknowledge discovered items.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          {/* ADD PORT */}
          <div className="bg-[#0D111A] p-5 rounded-xl border border-slate-800 space-y-3.5 shadow-xs">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Plus className="w-3.5 h-3.5 text-cyan-400" />
              <span>Add Custom Insecure Port</span>
            </h3>
            <div className="space-y-3">
              <div>
                <label className="text-[10px] font-semibold text-slate-400 block mb-1 uppercase tracking-wider">Port Number</label>
                <input 
                  type="text" 
                  value={newPort.port} 
                  onChange={e => setNewPort({...newPort, port: e.target.value.replace(/\D/g, '')})} 
                  className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-white outline-none focus:border-cyan-500 font-mono" 
                  placeholder="e.g. 5000" 
                />
              </div>
              <div>
                <label className="text-[10px] font-semibold text-slate-400 block mb-1 uppercase tracking-wider">Service Label</label>
                <input 
                  type="text" 
                  value={newPort.label} 
                  onChange={e => setNewPort({...newPort, label: e.target.value})} 
                  className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-white outline-none focus:border-cyan-500" 
                  placeholder="e.g. Internal Debug Service" 
                />
              </div>
              <div>
                <label className="text-[10px] font-semibold text-slate-400 block mb-1 uppercase tracking-wider">Criticality</label>
                <select 
                  value={newPort.criticality} 
                  onChange={e => setNewPort({...newPort, criticality: e.target.value as Severity})} 
                  className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-white focus:border-cyan-500"
                >
                  <option value="LOW">Low</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="HIGH">High</option>
                  <option value="CRITICAL">Critical</option>
                </select>
              </div>
              <button 
                onClick={addCustomPort} 
                className="w-full bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 font-semibold py-2 rounded-lg text-xs transition-colors"
              >
                Add Port to Matrix
              </button>
            </div>
          </div>

          {/* ADD SERVICE OBJECT */}
          <div className="bg-[#0D111A] p-5 rounded-xl border border-slate-800 space-y-3.5 shadow-xs">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Plus className="w-3.5 h-3.5 text-cyan-400" />
              <span>Add Custom Insecure Service</span>
            </h3>
            <div className="space-y-3">
              <div>
                <label className="text-[10px] font-semibold text-slate-400 block mb-1 uppercase tracking-wider">Object Name</label>
                <input 
                  type="text" 
                  value={newService.name} 
                  onChange={e => setNewService({...newService, name: e.target.value})} 
                  className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-white outline-none focus:border-cyan-500 font-mono" 
                  placeholder="e.g. DB_DIRECT_ACCESS" 
                />
              </div>
              <div>
                <label className="text-[10px] font-semibold text-slate-400 block mb-1 uppercase tracking-wider">Criticality</label>
                <select 
                  value={newService.criticality} 
                  onChange={e => setNewService({...newService, criticality: e.target.value as Severity})} 
                  className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-white focus:border-cyan-500"
                >
                  <option value="LOW">Low</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="HIGH">High</option>
                  <option value="CRITICAL">Critical</option>
                </select>
              </div>
              <button 
                onClick={() => addCustomService()} 
                className="w-full bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 font-semibold py-2 rounded-lg text-xs transition-colors"
              >
                Add Service to Registry
              </button>
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex gap-3">
             <AlertTriangle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
             <p className="text-[11px] text-slate-400 leading-relaxed">
               <strong className="text-slate-300">Matching Logic:</strong> Insecure Service Objects are evaluated by exact and group name matching. When rules reference these objects, the engine associates them with the defined severity.
             </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
