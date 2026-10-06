import React, { useState } from 'react';
import axios from 'axios';
import { X, Send, Loader2, ShieldAlert } from 'lucide-react';

interface PublishModalProps {
  isOpen: boolean;
  onClose: () => void;
  apiUrl: string;
  auth: { credential_id: string; private_key_b64: string; org_id: string };
  onSuccess: () => void;
}

export default function PublishModal({ isOpen, onClose, apiUrl, auth, onSuccess }: PublishModalProps) {
  const [pattern, setPattern] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pattern.trim()) return;
    
    setLoading(true);
    setError('');
    
    try {
      await axios.post(`${apiUrl}/publish`, {
        credential_id: auth.credential_id,
        private_key_b64: auth.private_key_b64,
        pattern: pattern.trim()
      });
      onSuccess();
      onClose();
      setPattern('');
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to publish threat');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md bg-card border border-border/50 rounded-xl shadow-2xl flex flex-col animate-in fade-in zoom-in-95 duration-200">
        <div className="flex items-center justify-between p-5 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-destructive/10 rounded-lg">
              <ShieldAlert className="w-5 h-5 text-destructive" />
            </div>
            <h2 className="text-lg font-bold font-mono tracking-tight">Publish Threat</h2>
          </div>
          <button onClick={onClose} className="p-2 text-muted-foreground hover:text-foreground hover:bg-white/5 rounded-lg transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-6">
          <div className="space-y-2">
            <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
              Malicious Indicator (IP, Domain, Hash)
            </label>
            <input
              type="text"
              placeholder="e.g. 203.0.113.42 or evil-domain.com"
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              className="w-full bg-black/50 border border-border/50 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-destructive focus:ring-1 focus:ring-destructive transition-all font-mono"
              autoFocus
              required
            />
          </div>

          {error && (
            <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive text-xs font-mono break-words">
              {error}
            </div>
          )}

          <div className="bg-white/5 border border-white/10 rounded-lg p-3">
            <p className="text-xs font-mono text-muted-foreground leading-relaxed">
              Publishing as <strong className="text-primary">{auth.org_id}</strong>. 
              This indicator will be cryptographically signed with your Ed25519 private key and gossiped to all peers.
            </p>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-white/5 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !pattern.trim()}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-destructive hover:bg-destructive/90 text-destructive-foreground flex items-center gap-2 disabled:opacity-50 transition-colors"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              Sign & Publish
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
