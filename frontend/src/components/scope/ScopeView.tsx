import React, { useState } from 'react';
import {
  Shield,
  PlusCircle,
  Trash2,
  CheckCircle2,
  Crosshair,
  AlertTriangle,
  RotateCcw,
  Layers,
  Lock,
} from 'lucide-react';
import { useScopeStore } from '../../store/useScopeStore';
import { api } from '../../services/api';

export const ScopeView: React.FC = () => {
  const {
    scopes,
    activeScopeId,
    setActiveScopeId,
    fetchScopes,
    triggerPerimeter,
    setActiveWorkspace,
  } = useScopeStore();

  const [target, setTarget] = useState('192.168.1.5');
  const [allowedPorts, setAllowedPorts] = useState('80,443,8080');
  const [excludedPorts, setExcludedPorts] = useState('22');
  const [excludedEndpoints, setExcludedEndpoints] = useState('/admin,/internal');
  const [engagementNote, setEngagementNote] = useState('Authorized lab security evaluation for target perimeter.');
  const [attested, setAttested] = useState(true);
  const [allowedActions, setAllowedActions] = useState<string[]>(['recon', 'active_validation']);
  
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!target.trim()) {
      setFormError('Target domain or IP address is required.');
      return;
    }
    if (!attested) {
      setFormError('You must attest that this target is an authorized lab environment.');
      return;
    }

    setSubmitting(true);
    try {
      const created = await api.createScope({
        target: target.trim(),
        allowed_ports: allowedPorts.trim(),
        excluded_ports: excludedPorts.trim(),
        excluded_endpoints: excludedEndpoints.trim(),
        engagement_note: engagementNote.trim(),
        authorized_lab_attested: attested,
        allowed_actions: allowedActions,
      });

      await fetchScopes();
      setActiveScopeId(created.id);
      triggerPerimeter();
      
      // Auto-redirect to assessment workspace
      setTimeout(() => {
        setActiveWorkspace('assessment');
      }, 700);
    } catch (err: any) {
      setFormError(err.message || 'Failed to register scope.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (scopeId: string) => {
    if (!window.confirm('Delete this authorized scope and its associated assessment data?')) return;
    try {
      await api.deleteScope(scopeId);
      await fetchScopes();
    } catch (err: any) {
      alert(err.message || 'Failed to delete scope');
    }
  };

  const handleReset = async () => {
    if (!window.confirm('CRITICAL: Reset all scopes, scans, findings, and audit records?')) return;
    setResetting(true);
    try {
      await api.resetSystem();
      await fetchScopes();
    } catch (err: any) {
      alert(err.message || 'Failed to reset system');
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="w-full max-w-[1700px] mx-auto px-6 lg:px-12 py-8">
      {/* Hero Section matching Landing-page.jpg typography */}
      <div className="relative text-center mb-12">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#7D58FD]/10 border border-[#7D58FD]/30 text-[#30E1DB] text-sm font-mono mb-4">
          <Shield className="w-4 h-4" />
          GOVERNANCE & PERIMETER CONTROL
        </div>
        <h1 className="text-4xl md:text-5xl font-display font-semibold text-[#ECE9F7] tracking-tight mb-3">
          Authorized Scope Registration
        </h1>
        <p className="text-sm md:text-base text-[#8A86A3] max-w-3xl mx-auto font-sans leading-relaxed">
          Calibrate defensive boundaries. Autonomous assessment tools and advisory engines operate strictly within confirmed authorization limits.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left: Registration Form Card */}
        <div className="lg:col-span-7">
          <div className="glass-panel rounded-2xl p-6 md:p-8">
            <div className="flex items-center justify-between pb-4 border-b border-[#7D58FD]/20 mb-6">
              <h2 className="text-xl font-semibold text-[#ECE9F7] flex items-center gap-2.5">
                <PlusCircle className="w-5 h-5 text-[#7D58FD]" />
                Calibrate New Target Boundary
              </h2>
              <span className="text-xs font-mono text-[#8A86A3]">RFC 1122 / CIDR Compliant</span>
            </div>

            {formError && (
              <div className="mb-6 p-4 rounded-xl bg-[#FF4D6D]/10 border border-[#FF4D6D]/30 flex items-start gap-3 text-sm text-[#FF4D6D]">
                <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                <span>{formError}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-5">
              <div>
                <label className="block text-sm font-semibold text-[#ECE9F7] uppercase tracking-wider mb-2">
                  Target Domain or Host / CIDR Range <span className="text-[#30E1DB]">*</span>
                </label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g. 192.168.1.5, scanme.nmap.org, 10.0.0.0/24"
                  className="w-full px-4 py-3 rounded-xl bg-[#0F0D18]/80 border border-[#7D58FD]/30 text-[#ECE9F7] text-sm md:text-base font-mono placeholder-[#8A86A3]/50 focus:outline-none focus:border-[#7D58FD] focus:ring-1 focus:ring-[#7D58FD] transition-all"
                  required
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-semibold text-[#ECE9F7] uppercase tracking-wider mb-2">
                    Allowed Ports <span className="text-[#30E1DB]">*</span>
                  </label>
                  <input
                    type="text"
                    value={allowedPorts}
                    onChange={(e) => setAllowedPorts(e.target.value)}
                    placeholder="80, 443, 8080"
                    className="w-full px-4 py-3 rounded-xl bg-[#0F0D18]/80 border border-[#7D58FD]/30 text-[#ECE9F7] text-sm md:text-base font-mono placeholder-[#8A86A3]/50 focus:outline-none focus:border-[#7D58FD] transition-all"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-semibold text-[#8A86A3] uppercase tracking-wider mb-2">
                    Excluded Ports (Optional)
                  </label>
                  <input
                    type="text"
                    value={excludedPorts}
                    onChange={(e) => setExcludedPorts(e.target.value)}
                    placeholder="22, 25, 3389"
                    className="w-full px-4 py-3 rounded-xl bg-[#0F0D18]/80 border border-[#7D58FD]/30 text-[#ECE9F7] text-sm md:text-base font-mono placeholder-[#8A86A3]/50 focus:outline-none focus:border-[#7D58FD] transition-all"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-semibold text-[#8A86A3] uppercase tracking-wider mb-2">
                  Excluded Endpoints / Paths (Optional)
                </label>
                <input
                  type="text"
                  value={excludedEndpoints}
                  onChange={(e) => setExcludedEndpoints(e.target.value)}
                  placeholder="/admin, /billing, /internal/*"
                  className="w-full px-4 py-3 rounded-xl bg-[#0F0D18]/80 border border-[#7D58FD]/30 text-[#ECE9F7] text-sm md:text-base font-mono placeholder-[#8A86A3]/50 focus:outline-none focus:border-[#7D58FD] transition-all"
                />
              </div>

              <div>
                <label className="block text-sm font-semibold text-[#ECE9F7] uppercase tracking-wider mb-2">
                  Engagement Note / Authorization Rationale <span className="text-[#30E1DB]">*</span>
                </label>
                <textarea
                  rows={2}
                  value={engagementNote}
                  onChange={(e) => setEngagementNote(e.target.value)}
                  placeholder="Engagement objective and authorized authorization context..."
                  className="w-full px-4 py-3 rounded-xl bg-[#0F0D18]/80 border border-[#7D58FD]/30 text-[#ECE9F7] text-sm md:text-base placeholder-[#8A86A3]/50 focus:outline-none focus:border-[#7D58FD] transition-all"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-semibold text-[#ECE9F7] uppercase tracking-wider mb-2">
                  Permitted Action Classes
                </label>
                <div className="flex flex-wrap gap-3">
                  {[
                    { id: 'recon', label: 'Passive Recon (Nmap, Headers)' },
                    { id: 'active_validation', label: 'Active Validation (ZAP, Nikto)' },
                    { id: 'configuration_audit', label: 'Config Audit (Imported)' },
                  ].map((act) => {
                    const isChecked = allowedActions.includes(act.id);
                    return (
                      <button
                        key={act.id}
                        type="button"
                        onClick={() => {
                          if (isChecked) {
                            if (allowedActions.length > 1) {
                              setAllowedActions(allowedActions.filter((a) => a !== act.id));
                            }
                          } else {
                            setAllowedActions([...allowedActions, act.id]);
                          }
                        }}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                          isChecked
                            ? 'bg-[#7D58FD]/20 border-[#7D58FD] text-[#ECE9F7] shadow-glow-violet-sm'
                            : 'bg-[#0F0D18] border-[#7D58FD]/20 text-[#8A86A3] hover:text-[#ECE9F7]'
                        }`}
                      >
                        {isChecked ? '✓ ' : '+ '}
                        {act.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="pt-2">
                <label className="flex items-start gap-3 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={attested}
                    onChange={(e) => setAttested(e.target.checked)}
                    className="mt-1 w-4 h-4 rounded border-[#7D58FD]/50 bg-[#0F0D18] text-[#7D58FD] focus:ring-0 focus:ring-offset-0"
                  />
                  <span className="text-xs text-[#8A86A3] leading-relaxed">
                    I attest that this target is an authorized lab environment or client target under a signed Rules of Engagement agreement.
                  </span>
                </label>
              </div>

              <div className="pt-4">
                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full py-3.5 rounded-xl font-medium text-sm text-white bg-gradient-to-r from-[#7D58FD] to-[#5a36db] hover:from-[#8d6bff] hover:to-[#6c48e8] shadow-glow-violet hover:shadow-[0_0_30px_rgba(125,88,253,0.6)] transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  <Lock className="w-4 h-4 text-[#30E1DB]" />
                  {submitting ? 'Calibrating Perimeter...' : 'Register Authorized Scope →'}
                </button>
              </div>
            </form>
          </div>
        </div>

        {/* Right: Active Scope Cards & Scope Registry */}
        <div className="lg:col-span-5 space-y-6">
          <div className="glass-panel rounded-2xl p-6">
            <div className="flex items-center justify-between pb-3 border-b border-[#7D58FD]/20 mb-4">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-[#ECE9F7] flex items-center gap-2">
                <Layers className="w-4 h-4 text-[#30E1DB]" />
                Calibrated Target Posture
              </h3>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#7D58FD]/20 text-[#ECE9F7]">
                {scopes.length} Enrolled
              </span>
            </div>

            {scopes.length === 0 ? (
              <div className="text-center py-8">
                <Crosshair className="w-8 h-8 text-[#8A86A3] mx-auto mb-2 opacity-50" />
                <p className="text-sm text-[#8A86A3]">No scopes calibrated yet.</p>
                <p className="text-xs text-[#8A86A3]/70 mt-1">
                  Register a target boundary to unlock assessment tools.
                </p>
              </div>
            ) : (
              <div className="space-y-3 max-h-[460px] overflow-y-auto pr-1">
                {scopes.map((s) => {
                  const isSelected = s.id === activeScopeId;
                  return (
                    <div
                      key={s.id}
                      className={`p-4 rounded-xl border transition-all ${
                        isSelected
                          ? 'bg-[#1F1A30] border-[#30E1DB]/60 shadow-glow-cyan-sm'
                          : 'bg-[#0F0D18]/60 border-[#7D58FD]/15 hover:border-[#7D58FD]/40'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => setActiveScopeId(s.id)}
                            className="text-left font-mono font-semibold text-sm text-[#ECE9F7] hover:text-[#30E1DB] transition-colors"
                          >
                            {s.target}
                          </button>
                          {isSelected && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#30E1DB]/20 text-[#30E1DB] border border-[#30E1DB]/40 font-semibold">
                              ACTIVE
                            </span>
                          )}
                        </div>
                        <button
                          onClick={() => handleDelete(s.id)}
                          className="p-1 rounded text-[#8A86A3] hover:text-[#FF4D6D] transition-colors"
                          title="Delete scope"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>

                      <div className="text-xs text-[#8A86A3] line-clamp-2 mb-2">
                        {s.engagement_note}
                      </div>

                      <div className="flex items-center justify-between text-[11px] font-mono text-[#8A86A3]">
                        <span>Ports: {s.allowed_ports}</span>
                        {!isSelected && (
                          <button
                            onClick={() => {
                              setActiveScopeId(s.id);
                              setActiveWorkspace('assessment');
                            }}
                            className="text-[#7D58FD] hover:text-[#ECE9F7] transition-colors"
                          >
                            Select & Assess →
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Reset System Button */}
          <div className="p-4 rounded-xl bg-[#0F0D18]/50 border border-[#7D58FD]/15 flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-[#ECE9F7]">System Maintenance</div>
              <div className="text-[11px] text-[#8A86A3]">Clear all assessment logs & targets</div>
            </div>
            <button
              onClick={handleReset}
              disabled={resetting}
              className="px-3 py-1.5 rounded-lg text-xs font-mono text-[#FF4D6D] border border-[#FF4D6D]/30 hover:bg-[#FF4D6D]/10 transition-colors flex items-center gap-1.5"
            >
              <RotateCcw className="w-3 h-3" />
              {resetting ? 'Resetting...' : 'Reset System'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

