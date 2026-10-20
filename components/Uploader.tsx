
import React, { useState, useRef } from 'react';
import { Upload, FileText, CheckCircle, AlertCircle, RefreshCcw, Box, ShieldCheck, ArrowRight, UploadCloud, Network } from 'lucide-react';
import { FirewallRule, ColumnMapping, ServiceObject, NetworkObject } from '../types';
import { DEFAULT_MAPPINGS } from '../constants';
import { parsePortsAndServices } from '../engine/analyzer';

interface UploaderProps {
  onDataLoaded: (rules: FirewallRule[], serviceObjects: Map<string, ServiceObject>, networkObjects: Map<string, NetworkObject>) => void;
}

const Uploader: React.FC<UploaderProps> = ({ onDataLoaded }) => {
  const [policyFile, setPolicyFile] = useState<File | null>(null);
  const [serviceFile, setServiceFile] = useState<File | null>(null);
  const [networkFile, setNetworkFile] = useState<File | null>(null);
  const [policyRows, setPolicyRows] = useState<any[]>([]);
  const [serviceObjects, setServiceObjects] = useState<Map<string, ServiceObject>>(new Map());
  const [networkObjects, setNetworkObjects] = useState<Map<string, NetworkObject>>(new Map());
  const [policyHeaders, setPolicyHeaders] = useState<string[]>([]);
  const [mapping, setMapping] = useState<Partial<ColumnMapping>>({});
  const [isProcessing, setIsProcessing] = useState(false);

  const policyInputRef = useRef<HTMLInputElement>(null);
  const serviceInputRef = useRef<HTMLInputElement>(null);
  const networkInputRef = useRef<HTMLInputElement>(null);

  const MANDATORY_FIELDS = ['source', 'destination', 'destinationPort', 'action'];

  const parseCSVLine = (line: string): string[] => {
    const result: string[] = [];
    let curVal = "";
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (char === '"') inQuotes = !inQuotes;
      else if (char === ',' && !inQuotes) {
        result.push(curVal.trim());
        curVal = "";
      } else curVal += char;
    }
    result.push(curVal.trim());
    return result;
  };

  const handlePolicyUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setPolicyFile(file);
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
      const csvHeaders = parseCSVLine(lines[0]).map(h => h.replace(/^"|"$/g, ''));
      setPolicyHeaders(csvHeaders);

      const initialMapping: Partial<ColumnMapping> = {};
      DEFAULT_MAPPINGS.forEach(m => {
        const found = csvHeaders.find(h => 
          m.synonyms.some(syn => h.toLowerCase() === syn.toLowerCase() || h.toLowerCase().includes(syn.toLowerCase()))
        );
        if (found) (initialMapping as any)[m.field] = found;
      });
      setMapping(initialMapping);

      const parsed = lines.slice(1).map(line => {
        const values = parseCSVLine(line);
        const obj: any = {};
        csvHeaders.forEach((h, i) => obj[h] = (values[i] || '').replace(/^"|"$/g, ''));
        return obj;
      });
      setPolicyRows(parsed);
    };
    reader.readAsText(file);
  };

  const handleServiceUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setServiceFile(file);
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
      if (lines.length < 2) return;

      const headers = parseCSVLine(lines[0]).map(h => h.toLowerCase());
      const nameIdx = headers.findIndex(h => h.includes('service.name') || h === 'name');
      const typeIdx = headers.findIndex(h => h.includes('service.type') || h === 'type');
      const portIdx = headers.findIndex(h => h.includes('service.protocolport') || h.includes('port') || h.includes('protocol'));

      const map = new Map<string, ServiceObject>();
      lines.slice(1).forEach(line => {
        const vals = parseCSVLine(line);
        const name = vals[nameIdx]?.replace(/^"|"$/g, '');
        if (!name) return;

        const rawPorts = vals[portIdx]?.replace(/^"|"$/g, '') || '';
        map.set(name.toLowerCase(), {
          name,
          type: (vals[typeIdx] || 'Single') as any,
          ports: parsePortsAndServices(rawPorts),
          raw: rawPorts
        });
      });
      setServiceObjects(map);
    };
    reader.readAsText(file);
  };

  const handleNetworkUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setNetworkFile(file);
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
      if (lines.length < 2) return;

      const headers = parseCSVLine(lines[0]).map(h => h.toLowerCase());
      const nameIdx = headers.findIndex(h => h.includes('name'));
      const typeIdx = headers.findIndex(h => h.includes('type'));
      const valueIdx = headers.findIndex(h => h.includes('value') || h.includes('ip') || h.includes('subnet'));

      const map = new Map<string, NetworkObject>();
      lines.slice(1).forEach(line => {
        const vals = parseCSVLine(line);
        const name = vals[nameIdx]?.replace(/^"|"$/g, '');
        if (!name) return;

        const value = vals[valueIdx]?.replace(/^"|"$/g, '') || '';
        map.set(name.toLowerCase(), {
          name,
          type: vals[typeIdx] || 'Host',
          value
        });
      });
      setNetworkObjects(map);
    };
    reader.readAsText(file);
  };

  const processData = () => {
    setIsProcessing(true);
    setTimeout(() => {
      const finalRules: FirewallRule[] = policyRows.map((row, idx) => {
        const getVal = (field: keyof ColumnMapping) => {
          const mappedHeader = mapping[field];
          return mappedHeader ? row[mappedHeader] : '';
        };
        const rawAction = getVal('action').toString().toUpperCase();
        const action: any = (rawAction.includes('ALLOW') || rawAction.includes('PERMIT') || rawAction.includes('ACCEPT')) ? 'ALLOW' : 'DENY';
        const rawEnabled = getVal('enabled').toString().toLowerCase();
        const enabled = !(rawEnabled.includes('false') || rawEnabled === 'no' || rawEnabled.includes('disabled') || rawEnabled === '0');

        return {
          id: getVal('id').toString() || (idx + 1).toString(),
          name: getVal('name').toString() || `Rule ${idx + 1}`,
          source: getVal('source').toString() || 'any',
          destination: getVal('destination').toString() || 'any',
          sourcePort: getVal('sourcePort').toString() || 'any',
          destinationPort: getVal('destinationPort').toString() || 'any',
          service: getVal('description').toString() || '',
          protocol: (getVal('protocol').toString().toUpperCase() || 'ANY') as any,
          action,
          direction: getVal('direction').toString().toUpperCase() || 'UNKNOWN',
          enabled,
          description: getVal('description').toString(),
          originalRow: row
        };
      });
      onDataLoaded(finalRules, serviceObjects, networkObjects);
      setIsProcessing(false);
    }, 500);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 py-2">
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Policy Upload Card */}
        <div 
          onClick={() => policyInputRef.current?.click()}
          className={`relative border-2 border-dashed rounded-xl p-7 flex flex-col items-center justify-center cursor-pointer transition-colors ${
            policyFile 
              ? 'bg-[#0E1522] border-cyan-500/60' 
              : 'bg-[#0D111A] border-slate-800 hover:border-slate-600'
          }`}
        >
          {policyFile && (
            <div className="absolute top-3 right-3 text-cyan-400">
              <CheckCircle className="w-5 h-5" />
            </div>
          )}
          
          <div className={`p-4 rounded-lg mb-4 ${policyFile ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' : 'bg-slate-900 border border-slate-800 text-slate-400'}`}>
            <FileText className="w-8 h-8" />
          </div>
          <h3 className="font-bold text-base text-white mb-1">{policyFile ? 'Policy File Configured' : 'Firewall Rules CSV'}</h3>
          <p className="text-xs text-slate-400 text-center max-w-xs leading-relaxed">
            {policyFile ? `${policyRows.length} rule records parsed.` : 'Required. Click to browse or drop standard firewall policy export.'}
          </p>
          <input type="file" ref={policyInputRef} className="hidden" accept=".csv" onChange={handlePolicyUpload} />
          
          {!policyFile && (
            <span className="mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400">
               <UploadCloud className="w-3.5 h-3.5" /> Select Policy File
            </span>
          )}
        </div>

        {/* Network Objects Upload Card */}
        <div 
          onClick={() => networkInputRef.current?.click()}
          className={`relative border-2 border-dashed rounded-xl p-7 flex flex-col items-center justify-center cursor-pointer transition-colors ${
            networkFile 
              ? 'bg-[#0E1522] border-cyan-500/60' 
              : 'bg-[#0D111A] border-slate-800 hover:border-slate-600'
          }`}
        >
          {networkFile && (
            <div className="absolute top-3 right-3 text-cyan-400">
              <CheckCircle className="w-5 h-5" />
            </div>
          )}
          
          <div className={`p-4 rounded-lg mb-4 ${networkFile ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' : 'bg-slate-900 border border-slate-800 text-slate-400'}`}>
            <Network className="w-8 h-8" />
          </div>
          <h3 className="font-bold text-base text-white mb-1">{networkFile ? 'Network Objects Configured' : 'Network Objects (Optional)'}</h3>
          <p className="text-xs text-slate-400 text-center max-w-xs leading-relaxed">
            {networkFile ? `${networkObjects.size} network objects mapped.` : 'Enhance CIDR accuracy by mapping custom network objects.'}
          </p>
          <input type="file" ref={networkInputRef} className="hidden" accept=".csv" onChange={handleNetworkUpload} />

          {!networkFile && (
            <span className="mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400">
               <UploadCloud className="w-3.5 h-3.5" /> Browse Objects
            </span>
          )}
        </div>

        {/* Service Objects Upload Card */}
        <div 
          onClick={() => serviceInputRef.current?.click()}
          className={`relative border-2 border-dashed rounded-xl p-7 flex flex-col items-center justify-center cursor-pointer transition-colors ${
            serviceFile 
              ? 'bg-[#0E1522] border-cyan-500/60' 
              : 'bg-[#0D111A] border-slate-800 hover:border-slate-600'
          }`}
        >
          {serviceFile && (
            <div className="absolute top-3 right-3 text-cyan-400">
              <CheckCircle className="w-5 h-5" />
            </div>
          )}
          
          <div className={`p-4 rounded-lg mb-4 ${serviceFile ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' : 'bg-slate-900 border border-slate-800 text-slate-400'}`}>
            <Box className="w-8 h-8" />
          </div>
          <h3 className="font-bold text-base text-white mb-1">{serviceFile ? 'Service Objects Configured' : 'Service Objects (Optional)'}</h3>
          <p className="text-xs text-slate-400 text-center max-w-xs leading-relaxed">
            {serviceFile ? `${serviceObjects.size} service objects mapped.` : 'Dereference custom protocol and port definitions automatically.'}
          </p>
          <input type="file" ref={serviceInputRef} className="hidden" accept=".csv" onChange={handleServiceUpload} />

          {!serviceFile && (
            <span className="mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400">
               <UploadCloud className="w-3.5 h-3.5" /> Browse Services
            </span>
          )}
        </div>
      </div>

      {policyFile && (
        <div className="bg-[#0D111A] border border-slate-800 rounded-xl p-6 space-y-6 shadow-xs">
          <div className="flex items-center gap-3 border-b border-slate-800 pb-4">
             <div className="p-2 bg-slate-900 border border-slate-800 rounded-lg text-cyan-400">
                <ShieldCheck className="w-5 h-5" />
             </div>
             <div>
                <h3 className="text-base font-bold text-white tracking-tight">CSV Schema Field Mapping</h3>
                <p className="text-xs text-slate-400">Map your exported column names to the RuleGuardX audit engine attributes</p>
             </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4">
               {DEFAULT_MAPPINGS.map(m => (
                  <div key={m.field} className="space-y-1">
                    <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                      {m.field} {MANDATORY_FIELDS.includes(m.field) && <span className="text-rose-400">*</span>}
                    </label>
                    <div className="relative">
                      <select 
                        value={mapping[m.field as keyof ColumnMapping] || ''} 
                        onChange={(e) => setMapping({...mapping, [m.field]: e.target.value})}
                        className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none appearance-none transition-colors"
                      >
                        <option value="" className="text-slate-500">-- Auto Detect --</option>
                        {policyHeaders.map(h => <option key={h} value={h} className="text-slate-200">{h}</option>)}
                      </select>
                      <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-slate-500">
                        <ArrowRight className="w-3.5 h-3.5 rotate-90" />
                      </div>
                    </div>
                  </div>
                ))}
            </div>

            <div className="space-y-4">
              <div className="bg-slate-900/60 rounded-xl p-5 border border-slate-800 space-y-4 sticky top-6">
                 <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">Pre-Audit Summary</h4>
                    <div className="space-y-2.5 text-xs">
                        <div className="flex justify-between items-center pb-2 border-b border-slate-800">
                          <span className="text-slate-400">Total Policy Rules</span>
                          <span className="font-mono font-bold text-white tabular-nums">{policyRows.length}</span>
                        </div>
                        <div className="flex justify-between items-center pb-2 border-b border-slate-800">
                          <span className="text-slate-400">Service Objects</span>
                          <span className="font-mono font-bold text-white tabular-nums">{serviceObjects.size}</span>
                        </div>
                        <div className="flex justify-between items-center pb-2 border-b border-slate-800">
                          <span className="text-slate-400">Network Objects</span>
                          <span className="font-mono font-bold text-white tabular-nums">{networkObjects.size}</span>
                        </div>
                    </div>
                 </div>
                 
                 <button 
                  onClick={processData}
                  disabled={isProcessing}
                  className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-semibold py-2.5 px-4 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 text-xs uppercase tracking-wider shadow-xs"
                >
                  {isProcessing ? (
                    <>
                      <RefreshCcw className="w-4 h-4 animate-spin" />
                      <span>Executing Engine...</span>
                    </>
                  ) : (
                    <>
                      <span>Run Security Audit</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Uploader;
