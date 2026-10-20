import React from 'react';
import { 
  Shield, 
  LayoutDashboard, 
  FileWarning, 
  Table, 
  FileCode, 
  Settings as SettingsIcon, 
  Layers, 
  BookOpen, 
  Github, 
  Linkedin, 
  Globe, 
  Search, 
  Menu, 
  X, 
  ExternalLink,
  CheckCircle2
} from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isAnalyzed: boolean;
}

const Layout: React.FC<LayoutProps> = ({ children, activeTab, setActiveTab, isAnalyzed }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, disabled: !isAnalyzed },
    { id: 'findings', label: 'Findings', icon: FileWarning, disabled: !isAnalyzed },
    { id: 'hygiene', label: 'Hygiene', icon: Layers, disabled: !isAnalyzed },
    { id: 'rules', label: 'Rules Data', icon: Table, disabled: !isAnalyzed },
    { id: 'docs', label: 'Documentation', icon: BookOpen, disabled: false },
    { id: 'settings', label: 'Settings', icon: SettingsIcon, disabled: false },
    { id: 'import', label: 'Import CSV', icon: FileCode, disabled: false },
  ];

  const currentDate = new Date().toLocaleDateString('en-US', { 
    weekday: 'short', 
    month: 'short', 
    day: 'numeric',
    year: 'numeric' 
  });

  const getTabTitle = (tab: string) => {
    switch (tab) {
      case 'dashboard': return 'Executive Security Dashboard';
      case 'findings': return 'Security Vulnerability Findings';
      case 'hygiene': return 'Policy Hygiene & Correlation Analysis';
      case 'rules': return 'Access Control Rules Directory';
      case 'docs': return 'Audit Methodology & Compliance Standards';
      case 'settings': return 'Audit Engine Configuration';
      case 'import': return 'Firewall Policy Ingestion';
      default: return 'Security Audit Console';
    }
  };

  return (
    <div className="min-h-screen bg-[#080B11] text-slate-100 flex font-sans selection:bg-cyan-500/20">
      
      {/* Mobile Menu Overlay */}
      {mobileMenuOpen && (
        <div 
          className="fixed inset-0 z-50 bg-black/70 lg:hidden backdrop-blur-xs" 
          onClick={() => setMobileMenuOpen(false)} 
        />
      )}

      {/* Sidebar Navigation */}
      <aside className={`fixed top-0 left-0 z-50 h-screen w-64 bg-[#0D111A] border-r border-slate-800 flex flex-col transition-transform duration-200 ease-in-out lg:translate-x-0 ${mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        
        {/* Brand Area */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-slate-900 border border-slate-700/80 flex items-center justify-center text-cyan-400 shadow-xs">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="text-base font-bold tracking-tight text-white">RuleGuard</span>
                <span className="text-base font-extrabold text-cyan-400">X</span>
              </div>
              <p className="text-[10px] text-slate-400 font-medium tracking-wide">Enterprise Policy Auditor</p>
            </div>
          </div>
          <button 
            onClick={() => setMobileMenuOpen(false)} 
            className="lg:hidden p-1.5 text-slate-400 hover:text-white rounded-md hover:bg-slate-800"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider px-3 mb-2">
            Navigation
          </div>
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  if (!item.disabled) {
                    setActiveTab(item.id);
                    setMobileMenuOpen(false);
                  }
                }}
                disabled={item.disabled}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors text-left font-medium ${
                  isActive 
                    ? 'bg-slate-800 text-white border-l-2 border-cyan-400 pl-[10px]' 
                    : item.disabled 
                      ? 'text-slate-400 cursor-not-allowed opacity-40' 
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <item.icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span className="truncate">{item.label}</span>
                {item.id === 'import' && !isAnalyzed && (
                  <span className="ml-auto text-[10px] font-semibold text-cyan-400 uppercase tracking-wider">
                    Ready
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Sidebar Footer with Verified Creator & Platform Attribution */}
        <div className="p-4 border-t border-slate-800 space-y-3 bg-[#0A0D15]">
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span className="font-semibold text-slate-200">Engine Core</span>
            <span className="font-mono text-[11px] text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" />
              v2.1 Offline
            </span>
          </div>

          <div className="pt-2 border-t border-slate-800/80 space-y-2">
            <a 
              href="https://vectrionx.com/" 
              target="_blank" 
              rel="noopener noreferrer"
              className="flex items-center justify-between text-xs text-slate-300 hover:text-cyan-400 transition-colors py-1 group"
            >
              <span className="flex items-center gap-2">
                <Globe className="w-3.5 h-3.5 text-slate-400 group-hover:text-cyan-400" />
                <span>vectrionx.com</span>
              </span>
              <ExternalLink className="w-3 h-3 opacity-50 group-hover:opacity-100" />
            </a>

            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center gap-2">
                <a 
                  href="https://github.com/VectrionX/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="p-1.5 text-slate-400 hover:text-white rounded-md hover:bg-slate-800 transition-colors"
                  title="VectrionX on GitHub"
                >
                  <Github className="w-4 h-4" />
                </a>
                <a 
                  href="https://www.linkedin.com/in/mag99" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="p-1.5 text-slate-400 hover:text-cyan-400 rounded-md hover:bg-slate-800 transition-colors"
                  title="LinkedIn Profile"
                >
                  <Linkedin className="w-4 h-4" />
                </a>
              </div>
              <span className="text-[11px] text-slate-400 font-medium">VectrionX</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Viewport */}
      <div className="flex-1 lg:ml-64 flex flex-col min-h-screen min-w-0">
        
        {/* Top Header */}
        <header className="sticky top-0 z-40 bg-[#0D111A]/95 backdrop-blur-sm border-b border-slate-800 px-6 py-3.5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button 
              onClick={() => setMobileMenuOpen(true)} 
              className="lg:hidden p-2 text-slate-400 hover:text-white rounded-md hover:bg-slate-800"
              aria-label="Open navigation"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div>
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <span>RuleGuardX</span>
                <span>/</span>
                <span className="text-slate-300 font-medium">{getTabTitle(activeTab)}</span>
              </div>
              <h2 className="text-base font-bold text-white tracking-tight mt-0.5">
                {getTabTitle(activeTab)}
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* System Status Indicator */}
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-md text-xs font-medium text-slate-300">
              <span className={`w-2 h-2 rounded-full ${isAnalyzed ? 'bg-emerald-400' : 'bg-slate-500'}`} />
              <span>{isAnalyzed ? 'Audit Active' : 'Awaiting Policy CSV'}</span>
            </div>

            <div className="hidden md:block text-xs font-mono text-slate-400 px-2.5 py-1.5 bg-slate-900/60 border border-slate-800/80 rounded-md">
              {currentDate}
            </div>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 p-6 lg:p-8 max-w-[1600px] w-full mx-auto">
          {children}
        </main>

      </div>
    </div>
  );
};

export default Layout;
