import React, { useState, useEffect } from 'react';
import { Settings, Save, CheckCircle, AlertCircle, Info, Zap } from 'lucide-react';
import { getSettings, updateSetting } from '../services/socService';
import LoadingSpinner from '../components/common/LoadingSpinner';
import ErrorBanner from '../components/common/ErrorBanner';
import { useAuth } from '../auth/AuthContext';

const SETTING_METADATA = {
  alertThresholdConfidence: {
    label: 'Alert Threshold Confidence',
    unit: '% (0 - 100)',
    type: 'number',
    min: 0,
    max: 100,
    help: 'Minimum model confidence required to trigger a HIGH severity alert. Demotes below-threshold attacks to MEDIUM.'
  },
  enableAutoResolution: {
    label: 'Enable Auto-Resolution',
    unit: 'Toggle (Boolean)',
    type: 'boolean',
    help: 'Automatically resolves matching open threat alerts when clean benign traffic resumes from the same source IP or flow.'
  },
  maxLogRetentionDays: {
    label: 'Max Log Retention Period',
    unit: 'Days (1 - 3650)',
    type: 'number',
    min: 1,
    max: 3650,
    help: 'Lifecycle retention threshold. Automated retention worker purges prediction logs older than this duration.'
  },
  systemNotificationEmail: {
    label: 'System Notification Email',
    unit: 'Email Address',
    type: 'email',
    help: 'Recipient email address dynamically configured to receive automated SOC security digests and threat reports.'
  }
};

const SettingsPage = () => {
  const { role } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [settings, setSettings] = useState([]);
  const [savingKey, setSavingKey] = useState(null);
  const [saveErrors, setSaveErrors] = useState({});
  const [successMsg, setSuccessMsg] = useState(null);

  const fetchSettings = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getSettings();
      setSettings(res.data || []);
    } catch (err) {
      setError(err.message || 'Failed to fetch settings from backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleValueChange = (key, val) => {
    setSettings(prev => prev.map(s => s.key === key ? { ...s, value: val } : s));
    if (saveErrors[key]) {
      setSaveErrors(prev => {
        const next = { ...prev };
        delete next[key];
        return next;
      });
    }
  };

  const handleSaveSetting = async (setting) => {
    setSavingKey(setting.key);
    setSuccessMsg(null);
    setSaveErrors(prev => {
      const next = { ...prev };
      delete next[setting.key];
      return next;
    });

    try {
      await updateSetting(setting.key, setting.value, setting.description);
      setSuccessMsg(`Setting '${setting.key}' saved successfully. Runtime behavior updated immediately.`);
      setTimeout(() => setSuccessMsg(null), 4000);
    } catch (err) {
      const msg = err.response?.data?.error?.message || err.message || 'Failed to update setting';
      setSaveErrors(prev => ({ ...prev, [setting.key]: msg }));
    } finally {
      setSavingKey(null);
    }
  };

  if (loading) return <LoadingSpinner message="Loading application settings..." />;
  if (error) return <ErrorBanner message={error} onRetry={fetchSettings} title="Settings Error" />;

  return (
    <div>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Settings size={22} style={{ color: 'var(--accent-cyan)' }} />
          System & Dashboard Settings
        </h2>
        <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
          Configure dynamic application parameters managed by the backend
        </p>
      </div>

      {role !== 'ADMIN' && (
        <div style={{ background: 'rgba(59, 130, 246, 0.12)', border: '1px solid rgba(59, 130, 246, 0.3)', color: '#93c5fd', padding: '0.75rem 1rem', borderRadius: '8px', marginBottom: '1.25rem', fontSize: '0.825rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Info size={16} />
          Read-Only Mode: Settings modification requires an account with the ADMIN role.
        </div>
      )}

      {successMsg && (
        <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#34d399', padding: '0.75rem 1rem', borderRadius: '8px', marginBottom: '1.25rem', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <CheckCircle size={16} />
          {successMsg}
        </div>
      )}

      <div className="soc-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Zap size={16} style={{ color: 'var(--accent-cyan)' }} />
            Configurable Parameters
          </h3>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', background: 'rgba(255,255,255,0.05)', padding: '0.25rem 0.6rem', borderRadius: '4px' }}>
            Hot-Reload: Changes take effect dynamically without server restarts
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {settings.map((setting) => {
            const meta = SETTING_METADATA[setting.key] || {};
            const fieldError = saveErrors[setting.key];

            return (
              <div 
                key={setting.key}
                style={{
                  background: '#0f172a',
                  padding: '1.25rem',
                  borderRadius: '8px',
                  border: fieldError ? '1px solid rgba(244, 63, 94, 0.5)' : '1px solid var(--border-color)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                  <div style={{ flex: 1, minWidth: '240px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontWeight: 600, color: 'var(--accent-cyan)', fontSize: '0.9rem' }}>
                        {meta.label || setting.key}
                      </span>
                      <code>{setting.key}</code>
                      {meta.unit && (
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', background: 'rgba(255,255,255,0.06)', padding: '0.1rem 0.4rem', borderRadius: '4px' }}>
                          {meta.unit}
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                      {meta.help || setting.description || 'System setting parameter'}
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    {typeof setting.value === 'boolean' ? (
                      <select
                        value={setting.value ? 'true' : 'false'}
                        onChange={(e) => handleValueChange(setting.key, e.target.value === 'true')}
                        disabled={role !== 'ADMIN'}
                        className="form-select"
                        style={{ padding: '0.45rem 0.75rem', minWidth: '150px' }}
                      >
                        <option value="true">Enabled (True)</option>
                        <option value="false">Disabled (False)</option>
                      </select>
                    ) : typeof setting.value === 'number' ? (
                      <input
                        type="number"
                        value={setting.value}
                        onChange={(e) => handleValueChange(setting.key, parseFloat(e.target.value))}
                        disabled={role !== 'ADMIN'}
                        min={meta.min}
                        max={meta.max}
                        className="form-input"
                        style={{ width: '130px', padding: '0.45rem 0.75rem' }}
                      />
                    ) : (
                      <input
                        type="text"
                        value={setting.value}
                        onChange={(e) => handleValueChange(setting.key, e.target.value)}
                        disabled={role !== 'ADMIN'}
                        className="form-input"
                        style={{ width: '240px', padding: '0.45rem 0.75rem' }}
                      />
                    )}

                    <button
                      onClick={() => handleSaveSetting(setting)}
                      disabled={role !== 'ADMIN' || savingKey === setting.key}
                      className="btn btn-primary"
                      style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem', opacity: role !== 'ADMIN' ? 0.5 : 1 }}
                      title={role !== 'ADMIN' ? 'Only ADMIN can modify system settings' : ''}
                    >
                      <Save size={14} />
                      {savingKey === setting.key ? 'Saving...' : 'Save'}
                    </button>
                  </div>
                </div>

                {fieldError && (
                  <div style={{ background: 'rgba(244, 63, 94, 0.15)', border: '1px solid rgba(244, 63, 94, 0.3)', padding: '0.5rem 0.75rem', borderRadius: '6px', color: '#f87171', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <AlertCircle size={14} />
                    {fieldError}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default SettingsPage;
