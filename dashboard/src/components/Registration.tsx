import React, { useState } from 'react';
import axios from 'axios';
import { Network, Shield, Loader2, Key } from 'lucide-react';

interface RegistrationProps {
  onLogin: (data: { org_id: string; credential_id: string; private_key_b64: string }) => void;
  apiUrl: string;
}

export default function Registration({ onLogin, apiUrl }: RegistrationProps) {
  const [orgId, setOrgId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId.trim()) return;
    
    setLoading(true);
    setError('');
    
    try {
      // Use the UI helper endpoint that generates the keypair and talks to Registrar
      const resp = await axios.post(`${apiUrl}/ui-register`, { org_id: orgId });
      onLogin(resp.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4 relative overflow-hidden">
      {/* Background decorations */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-primary/5 rounded-full blur-[120px] pointer-events-none" />
      
      <div className="w-full max-w-md bg-card/80 backdrop-blur-xl border border-border/50 rounded-2xl p-8 shadow-2xl relative z-10">
        <div className="flex flex-col items-center mb-8">
          <div className="relative mb-4">
            <Network className="h-12 w-12 text-primary" />
            <div className="absolute -top-1 -right-1 h-3 w-3 bg-primary rounded-full animate-pulse" />
          </div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-center">
            SWARM<span className="text-primary">SEC</span>
          </h1>
          <p className="text-sm text-muted-foreground font-mono mt-2 text-center">
            Node Authentication & Registration
          </p>
        </div>

        <form onSubmit={handleRegister} className="space-y-6">
          <div className="space-y-2">
            <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
              Organization Identifier
            </label>
            <div className="relative">
              <Shield className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="e.g. org-a, org-b, colluder-1"
                value={orgId}
                onChange={(e) => setOrgId(e.target.value)}
                className="w-full bg-black/50 border border-border/50 rounded-lg pl-10 pr-4 py-3 text-sm focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all font-mono"
                required
              />
            </div>
            <p className="text-[10px] text-muted-foreground font-mono mt-1">
              Must be in the Registrar's strict allowlist to join.
            </p>
          </div>

          {error && (
            <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive text-sm font-mono break-words">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !orgId.trim()}
            className="w-full cyber-button py-3 rounded-lg flex items-center justify-center gap-2 font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {loading ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : (
              <Key className="w-5 h-5" />
            )}
            {loading ? 'Authenticating...' : 'Generate Keys & Join Network'}
          </button>
        </form>

        <div className="mt-8 pt-6 border-t border-border/50 text-center">
          <p className="text-xs text-muted-foreground font-mono leading-relaxed">
            Local keypair generation happens on the Node. Your private key is stored securely in this browser session.
          </p>
        </div>
      </div>
    </div>
  );
}
