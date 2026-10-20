
import React from 'react';
import { FilterState, FilterClause, FilterField, FilterOperator } from '../types';
import { Search, Plus, Trash2, Filter, Settings2, HelpCircle, X } from 'lucide-react';

interface FilterBarProps {
  filters: FilterState;
  setFilters: React.Dispatch<React.SetStateAction<FilterState>>;
  categories: string[];
}

const FIELDS: { value: FilterField; label: string }[] = [
  { value: 'id', label: 'Rule ID' },
  { value: 'name', label: 'Rule Name' },
  { value: 'source', label: 'Source IP/Net' },
  { value: 'destination', label: 'Dest IP/Net' },
  { value: 'destinationPort', label: 'Port' },
  { value: 'protocol', label: 'Protocol' },
  { value: 'action', label: 'Action' },
  { value: 'severity', label: 'Risk Severity' },
  { value: 'category', label: 'Risk Category' },
  { value: 'description', label: 'Description' },
];

const OPERATORS: { value: FilterOperator; label: string }[] = [
  { value: 'CONTAINS', label: 'Contains' },
  { value: 'NOT_CONTAINS', label: 'Does Not Contain' },
  { value: 'EQUALS', label: 'Equals' },
  { value: 'NOT_EQUALS', label: 'Does Not Equal' },
  { value: 'STARTS_WITH', label: 'Starts With' },
  { value: 'ENDS_WITH', label: 'Ends With' },
  { value: 'GREATER_THAN', label: 'Greater Than' },
  { value: 'LESS_THAN', label: 'Less Than' },
];

const FilterBar: React.FC<FilterBarProps> = ({ filters, setFilters, categories }) => {
  const [isOpen, setIsOpen] = React.useState(true);

  const addClause = () => {
    const newClause: FilterClause = {
      id: Math.random().toString(36).substr(2, 9),
      field: 'name',
      operator: 'CONTAINS',
      value: '',
      logicalOperator: 'AND',
    };
    setFilters(prev => ({ ...prev, clauses: [...prev.clauses, newClause] }));
  };

  const removeClause = (id: string) => {
    setFilters(prev => ({ ...prev, clauses: prev.clauses.filter(c => c.id !== id) }));
  };

  const updateClause = (id: string, updates: Partial<FilterClause>) => {
    setFilters(prev => ({
      ...prev,
      clauses: prev.clauses.map(c => (c.id === id ? { ...c, ...updates } : c)),
    }));
  };

  const updateQuickSearch = (val: string) => {
    setFilters(prev => ({ ...prev, quickSearch: val }));
  };

  return (
    <div className="mb-6">
      <div className="bg-[#0D111A] border border-slate-800 rounded-xl overflow-hidden shadow-xs">
         {/* Search Input Area */}
         <div className="flex items-center px-4 py-2.5 gap-3">
             <Search className="w-4 h-4 text-slate-400 shrink-0" />
             <input 
                type="text"
                placeholder="Search rulebase by ID, name, source, destination, port, service..."
                value={filters.quickSearch}
                onChange={e => updateQuickSearch(e.target.value)}
                className="flex-1 bg-transparent border-none text-slate-200 placeholder:text-slate-500 focus:outline-none text-xs sm:text-sm"
             />
             <div className="h-6 w-[1px] bg-slate-800 mx-1" />
             <button 
                onClick={() => setIsOpen(!isOpen)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                  isOpen 
                    ? 'bg-slate-800 text-cyan-400 border border-slate-700' 
                    : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
                }`}
             >
                <Filter className="w-3.5 h-3.5" />
                <span>Filters</span>
                {filters.clauses.length > 0 && (
                   <span className="w-4 h-4 rounded-full bg-cyan-500/20 text-cyan-400 font-mono text-[10px] flex items-center justify-center font-bold">
                     {filters.clauses.length}
                   </span>
                )}
             </button>
         </div>
         
         {/* Expanded Filters */}
         {isOpen && (
             <div className="border-t border-slate-800 p-4 bg-[#090D15]">
                 <div className="flex items-center justify-between mb-3">
                    <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                       <Settings2 className="w-3.5 h-3.5 text-cyan-400" />
                       <span>Structured Query Conditions</span>
                    </h4>
                    {filters.clauses.length > 0 && (
                        <button 
                           onClick={() => setFilters({ clauses: [], quickSearch: '' })}
                           className="text-xs text-rose-400 hover:text-rose-300 font-medium flex items-center gap-1"
                        >
                           <Trash2 className="w-3 h-3" /> Clear All
                        </button>
                    )}
                 </div>

                 <div className="space-y-2.5">
                     {filters.clauses.map((clause, index) => (
                         <div key={clause.id} className="flex flex-col sm:flex-row items-start sm:items-center gap-2">
                             {index > 0 && (
                                 <div className="flex items-center bg-slate-900 p-0.5 rounded border border-slate-800">
                                     <button 
                                        onClick={() => updateClause(clause.id, { logicalOperator: 'AND' })}
                                        className={`px-2 py-0.5 text-[10px] font-bold rounded ${clause.logicalOperator === 'AND' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
                                     >AND</button>
                                     <button 
                                        onClick={() => updateClause(clause.id, { logicalOperator: 'OR' })}
                                        className={`px-2 py-0.5 text-[10px] font-bold rounded ${clause.logicalOperator === 'OR' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
                                     >OR</button>
                                 </div>
                             )}

                             <div className="flex-1 flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 w-full sm:w-auto">
                                 <select 
                                     value={clause.field}
                                     onChange={e => updateClause(clause.id, { field: e.target.value as FilterField })}
                                     className="bg-transparent text-xs font-semibold text-slate-200 outline-none cursor-pointer hover:text-white"
                                 >
                                     {FIELDS.map(f => <option key={f.value} value={f.value} className="bg-slate-900">{f.label}</option>)}
                                 </select>
                                 <div className="w-[1px] h-3.5 bg-slate-800" />
                                 <select 
                                     value={clause.operator}
                                     onChange={e => updateClause(clause.id, { operator: e.target.value as FilterOperator })}
                                     className="bg-transparent text-xs font-semibold text-cyan-400 outline-none cursor-pointer"
                                 >
                                     {OPERATORS.map(o => <option key={o.value} value={o.value} className="bg-slate-900">{o.label}</option>)}
                                 </select>
                                 <div className="w-[1px] h-3.5 bg-slate-800" />
                                 <input 
                                     type="text"
                                     value={clause.value}
                                     onChange={e => updateClause(clause.id, { value: e.target.value })}
                                     placeholder="Value..."
                                     className="bg-transparent text-xs text-white placeholder:text-slate-600 outline-none flex-1 min-w-[120px]"
                                 />
                                 <button onClick={() => removeClause(clause.id)} className="text-slate-500 hover:text-rose-400 p-0.5">
                                     <X className="w-3.5 h-3.5" />
                                 </button>
                             </div>
                         </div>
                     ))}

                     <button 
                        onClick={addClause}
                        className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-300 hover:text-white transition-colors bg-slate-800 hover:bg-slate-700/80 px-3 py-1.5 rounded-lg border border-slate-700/80"
                     >
                        <Plus className="w-3 h-3 text-cyan-400" /> Add Condition
                     </button>
                 </div>
             </div>
         )}
      </div>
    </div>
  );
};

export default FilterBar;
