import React, { useEffect } from 'react';
import { useScopeStore } from './store/useScopeStore';
import { TopNav } from './components/common/TopNav';
import { PerimeterEffect } from './components/common/PerimeterEffect';
import { PageTransition } from './components/common/PageTransition';
import { ScopeView } from './components/scope/ScopeView';
import { AssessmentView } from './components/assessment/AssessmentView';
import { AuditView } from './components/audit/AuditView';
import { IntegrationsView } from './components/integrations/IntegrationsView';
import { ReportView } from './components/report/ReportView';

export const App: React.FC = () => {
  const { activeWorkspace, fetchScopes } = useScopeStore();

  useEffect(() => {
    fetchScopes();
  }, [fetchScopes]);

  const renderActiveView = () => {
    switch (activeWorkspace) {
      case 'scope':
        return <ScopeView />;
      case 'assessment':
        return <AssessmentView />;
      case 'audit':
        return <AuditView />;
      case 'integrations':
        return <IntegrationsView />;
      case 'report':
        return <ReportView />;
      default:
        return <ScopeView />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0F0D18] text-[#ECE9F7] relative flex flex-col selection:bg-[#7D58FD]/30 selection:text-white">
      {/* Background Cybernetic Perspective Grid */}
      <div className="fixed inset-0 cyber-grid-floor pointer-events-none opacity-40 z-0" />

      {/* Ambient Radial Glow Arc (Matching Landing-page.jpg concentric arc motif) */}
      <div className="fixed top-[-180px] left-1/2 -translate-x-1/2 w-[900px] h-[550px] bg-gradient-to-b from-[#7D58FD]/15 via-[#7D58FD]/5 to-transparent rounded-full blur-3xl pointer-events-none z-0" />

      {/* Signature Safety Perimeter Glow Effect */}
      <PerimeterEffect />

      {/* Top Navigation */}
      <TopNav />

      {/* Main Content Stage with Modular Page Transitions */}
      <main className="relative z-10 flex-1 flex flex-col">
        <PageTransition transitionKey={activeWorkspace}>
          {renderActiveView()}
        </PageTransition>
      </main>

      {/* Footer */}
      <footer className="relative z-10 py-6 px-6 border-t border-[#7D58FD]/15 mt-auto text-center text-xs font-mono text-[#8A86A3]">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#30E1DB] animate-pulse" />
            <span>CIPHER LENS v2.2 // AUTONOMOUS VAPT ADVISORY SYSTEM</span>
          </div>
          <div>
            <span>AUTHORIZED TARGET LABS ONLY // CONSTITUTION PROTECTED</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
export default App;

