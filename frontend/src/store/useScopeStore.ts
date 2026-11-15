import { create } from 'zustand';
import { api } from '../services/api';
import { Scope } from '../types';

export type WorkspaceTab = 'scope' | 'assessment' | 'audit' | 'integrations' | 'report';

interface ScopeStore {
  scopes: Scope[];
  activeScopeId: string | null;
  activeWorkspace: WorkspaceTab;
  promptInput: string;
  isScanning: boolean;
  perimeterActive: boolean;
  loading: boolean;
  error: string | null;

  // Actions
  fetchScopes: () => Promise<void>;
  setActiveScopeId: (id: string | null) => void;
  setActiveWorkspace: (tab: WorkspaceTab) => void;
  setPromptInput: (text: string) => void;
  setIsScanning: (scanning: boolean) => void;
  triggerPerimeter: () => void;
  getActiveScope: () => Scope | undefined;
}

export const useScopeStore = create<ScopeStore>((set, get) => ({
  scopes: [],
  activeScopeId: null,
  activeWorkspace: 'scope',
  promptInput: '',
  isScanning: false,
  perimeterActive: false,
  loading: false,
  error: null,

  fetchScopes: async () => {
    set({ loading: true, error: null });
    try {
      const scopes = await api.listScopes();
      set({ scopes, loading: false });
      // Default to first scope if none selected or current selection missing
      const currentActive = get().activeScopeId;
      if (!currentActive || !scopes.some((s) => s.id === currentActive)) {
        if (scopes.length > 0) {
          set({ activeScopeId: scopes[0].id });
        } else {
          set({ activeScopeId: null });
        }
      }
    } catch (err: any) {
      set({ error: err.message, loading: false });
    }
  },

  setActiveScopeId: (id) => set({ activeScopeId: id }),
  setActiveWorkspace: (tab) => set({ activeWorkspace: tab }),
  setPromptInput: (text) => set({ promptInput: text }),
  setIsScanning: (isScanning) => set({ isScanning }),

  triggerPerimeter: () => {
    set({ perimeterActive: true });
    setTimeout(() => {
      set({ perimeterActive: false });
    }, 2000);
  },

  getActiveScope: () => {
    const { scopes, activeScopeId } = get();
    return scopes.find((s) => s.id === activeScopeId);
  },
}));

