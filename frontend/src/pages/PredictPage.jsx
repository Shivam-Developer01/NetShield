import React, { useState } from 'react';
import { Cpu, Send, CheckCircle, AlertTriangle, Zap, Layers, XCircle } from 'lucide-react';
import { submitPrediction } from '../services/socService';
import SeverityBadge from '../components/common/SeverityBadge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { useAuth } from '../auth/AuthContext';

const NSL_KDD_BENIGN_SAMPLE = {
  duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF',
  src_bytes: 215, dst_bytes: 4507, land: 0, wrong_fragment: 0,
  urgent: 0, hot: 0, num_failed_logins: 0, logged_in: 1,
  num_compromised: 0, root_shell: 0, su_attempted: 0, num_root: 0,
  num_file_creations: 0, num_shells: 0, num_access_files: 0,
  num_outbound_cmds: 0, is_host_login: 0, is_guest_login: 0,
  count: 1, srv_count: 1, serror_rate: 0.0, srv_serror_rate: 0.0,
  rerror_rate: 0.0, srv_rerror_rate: 0.0, same_srv_rate: 1.0,
  diff_srv_rate: 0.0, srv_diff_host_rate: 0.0, dst_host_count: 255,
  dst_host_srv_count: 255, dst_host_same_srv_rate: 1.0,
  dst_host_diff_srv_rate: 0.0, dst_host_same_src_port_rate: 0.0,
  dst_host_srv_diff_host_rate: 0.0, dst_host_serror_rate: 0.0,
  dst_host_srv_serror_rate: 0.0, dst_host_rerror_rate: 0.0,
  dst_host_srv_rerror_rate: 0.0
};

const NSL_KDD_DOS_SAMPLE = {
  duration: 0, protocol_type: 'tcp', service: 'private', flag: 'S0',
  src_bytes: 0, dst_bytes: 0, land: 0, wrong_fragment: 0,
  urgent: 0, hot: 0, num_failed_logins: 0, logged_in: 0,
  num_compromised: 0, root_shell: 0, su_attempted: 0, num_root: 0,
  num_file_creations: 0, num_shells: 0, num_access_files: 0,
  num_outbound_cmds: 0, is_host_login: 0, is_guest_login: 0,
  count: 128, srv_count: 6, serror_rate: 1.0, srv_serror_rate: 1.0,
  rerror_rate: 0.0, srv_rerror_rate: 0.0, same_srv_rate: 0.05,
  diff_srv_rate: 0.07, srv_diff_host_rate: 0.0, dst_host_count: 255,
  dst_host_srv_count: 6, dst_host_same_srv_rate: 0.02,
  dst_host_diff_srv_rate: 0.06, dst_host_same_src_port_rate: 0.0,
  dst_host_srv_diff_host_rate: 0.0, dst_host_serror_rate: 1.0,
  dst_host_srv_serror_rate: 1.0, dst_host_rerror_rate: 0.0,
  dst_host_srv_rerror_rate: 0.0
};

const NSL_KDD_PROBE_SAMPLE = {
  duration: 0, protocol_type: 'tcp', service: 'private', flag: 'REJ',
  src_bytes: 0, dst_bytes: 0, land: 0, wrong_fragment: 0,
  urgent: 0, hot: 0, num_failed_logins: 0, logged_in: 0,
  num_compromised: 0, root_shell: 0, su_attempted: 0, num_root: 0,
  num_file_creations: 0, num_shells: 0, num_access_files: 0,
  num_outbound_cmds: 0, is_host_login: 0, is_guest_login: 0,
  count: 229, srv_count: 10, serror_rate: 0.0, srv_serror_rate: 0.0,
  rerror_rate: 1.0, srv_rerror_rate: 1.0, same_srv_rate: 0.04,
  diff_srv_rate: 0.06, srv_diff_host_rate: 0.0, dst_host_count: 255,
  dst_host_srv_count: 10, dst_host_same_srv_rate: 0.04,
  dst_host_diff_srv_rate: 0.06, dst_host_same_src_port_rate: 0.0,
  dst_host_srv_diff_host_rate: 0.0, dst_host_serror_rate: 0.0,
  dst_host_srv_serror_rate: 0.0, dst_host_rerror_rate: 1.0,
  dst_host_srv_rerror_rate: 1.0
};

const NSL_KDD_U2R_SAMPLE = {
  duration: 184, protocol_type: 'tcp', service: 'telnet', flag: 'SF',
  src_bytes: 1511, dst_bytes: 2957, land: 0, wrong_fragment: 0,
  urgent: 0, hot: 3, num_failed_logins: 0, logged_in: 1,
  num_compromised: 2, root_shell: 1, su_attempted: 0, num_root: 0,
  num_file_creations: 1, num_shells: 0, num_access_files: 0,
  num_outbound_cmds: 0, is_host_login: 0, is_guest_login: 0,
  count: 1, srv_count: 1, serror_rate: 0.0, srv_serror_rate: 0.0,
  rerror_rate: 0.0, srv_rerror_rate: 0.0, same_srv_rate: 1.0,
  diff_srv_rate: 0.0, srv_diff_host_rate: 0.0, dst_host_count: 1,
  dst_host_srv_count: 3, dst_host_same_srv_rate: 1.0,
  dst_host_diff_srv_rate: 0.0, dst_host_same_src_port_rate: 1.0,
  dst_host_srv_diff_host_rate: 0.67, dst_host_serror_rate: 0.0,
  dst_host_srv_serror_rate: 0.0, dst_host_rerror_rate: 0.0,
  dst_host_srv_rerror_rate: 0.0
};

const CICIDS2017_BENIGN_SAMPLE = {
  "Destination Port": 80,
  "Flow Duration": 12500,
  "Total Fwd Packets": 2,
  "Total Backward Packets": 2,
  "Total Length of Fwd Packets": 40,
  "Total Length of Bwd Packets": 120,
  "Fwd Packet Length Max": 20,
  "Fwd Packet Length Min": 20,
  "Fwd Packet Length Mean": 20.0,
  "Bwd Packet Length Max": 60,
  "Bwd Packet Length Min": 60,
  "Bwd Packet Length Mean": 60.0,
  "Flow Bytes/s": 12800.0,
  "Flow Packets/s": 320.0,
  "Flow IAT Mean": 4166.6,
  "Flow IAT Std": 1200.0,
  "Flow IAT Max": 5000,
  "Flow IAT Min": 3000,
  "Fwd IAT Total": 12000,
  "Fwd IAT Mean": 6000.0,
  "Fwd IAT Std": 500.0,
  "Fwd IAT Max": 6500,
  "Fwd IAT Min": 5500,
  "Bwd IAT Total": 11000,
  "Bwd IAT Mean": 5500.0,
  "Bwd IAT Std": 400.0,
  "Bwd IAT Max": 6000,
  "Bwd IAT Min": 5000,
  "Fwd PSH Flags": 0,
  "Bwd PSH Flags": 0,
  "Fwd URG Flags": 0,
  "Bwd URG Flags": 0,
  "Fwd Header Length": 40,
  "Bwd Header Length": 40,
  "Fwd Packets/s": 160.0,
  "Bwd Packets/s": 160.0,
  "Min Packet Length": 20,
  "Max Packet Length": 60,
  "Packet Length Mean": 40.0,
  "Packet Length Std": 20.0,
  "Packet Length Variance": 400.0,
  "FIN Flag Count": 0,
  "SYN Flag Count": 1,
  "RST Flag Count": 0,
  "PSH Flag Count": 0,
  "ACK Flag Count": 1,
  "URG Flag Count": 0,
  "CWE Flag Count": 0,
  "ECE Flag Count": 0,
  "Down/Up Ratio": 1,
  "Average Packet Size": 40.0,
  "Avg Fwd Segment Size": 20.0,
  "Avg Bwd Segment Size": 60.0,
  "Fwd Header Length.1": 40,
  "Fwd Avg Bytes/Bulk": 0,
  "Fwd Avg Packets/Bulk": 0,
  "Fwd Avg Bulk Rate": 0,
  "Bwd Avg Bytes/Bulk": 0,
  "Bwd Avg Packets/Bulk": 0,
  "Bwd Avg Bulk Rate": 0,
  "Subflow Fwd Packets": 2,
  "Subflow Fwd Bytes": 40,
  "Subflow Bwd Packets": 2,
  "Subflow Bwd Bytes": 120,
  "Init_Win_bytes_forward": 8192,
  "Init_Win_bytes_backward": 255,
  "act_data_pkt_fwd": 1,
  "min_seg_size_forward": 20,
  "Active Mean": 0.0,
  "Active Std": 0.0,
  "Active Max": 0,
  "Active Min": 0,
  "Idle Mean": 0.0,
  "Idle Std": 0.0,
  "Idle Max": 0,
  "Idle Min": 0
};

const CICIDS2017_DDOS_SAMPLE = {
  "Destination Port": 80,
  "Flow Duration": 1293792,
  "Total Fwd Packets": 3,
  "Total Backward Packets": 7,
  "Total Length of Fwd Packets": 26,
  "Total Length of Bwd Packets": 11607,
  "Fwd Packet Length Max": 20,
  "Fwd Packet Length Min": 0,
  "Fwd Packet Length Mean": 8.666666667,
  "Bwd Packet Length Max": 4344,
  "Bwd Packet Length Min": 0,
  "Bwd Packet Length Mean": 1658.142857,
  "Flow Bytes/s": 8991.398927,
  "Flow Packets/s": 7.72921768,
  "Flow IAT Mean": 143754.6667,
  "Flow IAT Std": 430865.8055,
  "Flow IAT Max": 1292730,
  "Flow IAT Min": 2,
  "Fwd IAT Total": 747,
  "Fwd IAT Mean": 373.5,
  "Fwd IAT Std": 523.9661249,
  "Fwd IAT Max": 744,
  "Fwd IAT Min": 3,
  "Bwd IAT Total": 1293740,
  "Bwd IAT Mean": 215623.3333,
  "Bwd IAT Std": 527690.6273,
  "Bwd IAT Max": 1292730,
  "Bwd IAT Min": 2,
  "Fwd PSH Flags": 0,
  "Bwd PSH Flags": 0,
  "Fwd URG Flags": 0,
  "Bwd URG Flags": 0,
  "Fwd Header Length": 72,
  "Bwd Header Length": 152,
  "Fwd Packets/s": 2.318765304,
  "Bwd Packets/s": 5.410452376,
  "Min Packet Length": 0,
  "Max Packet Length": 4344,
  "Packet Length Mean": 1057.545455,
  "Packet Length Std": 1653.498432,
  "Packet Length Variance": 2734057.069,
  "FIN Flag Count": 0,
  "SYN Flag Count": 0,
  "RST Flag Count": 0,
  "PSH Flag Count": 1,
  "ACK Flag Count": 0,
  "URG Flag Count": 0,
  "CWE Flag Count": 0,
  "ECE Flag Count": 0,
  "Down/Up Ratio": 2,
  "Average Packet Size": 1163.3,
  "Avg Fwd Segment Size": 8.666666667,
  "Avg Bwd Segment Size": 1658.142857,
  "Fwd Header Length.1": 72,
  "Fwd Avg Bytes/Bulk": 0,
  "Fwd Avg Packets/Bulk": 0,
  "Fwd Avg Bulk Rate": 0,
  "Bwd Avg Bytes/Bulk": 0,
  "Bwd Avg Packets/Bulk": 0,
  "Bwd Avg Bulk Rate": 0,
  "Subflow Fwd Packets": 3,
  "Subflow Fwd Bytes": 26,
  "Subflow Bwd Packets": 7,
  "Subflow Bwd Bytes": 11607,
  "Init_Win_bytes_forward": 8192,
  "Init_Win_bytes_backward": 229,
  "act_data_pkt_fwd": 2,
  "min_seg_size_forward": 20,
  "Active Mean": 0,
  "Active Std": 0,
  "Active Max": 0,
  "Active Min": 0,
  "Idle Mean": 0,
  "Idle Std": 0,
  "Idle Max": 0,
  "Idle Min": 0
};

// Authentic CICIDS2017 DoS Hulk sample from Wednesday-workingHours.pcap_ISCX.csv (Row 74860)
// Verified Ground Truth: DoS Hulk | Model Accuracy on this sample: 99.69% DoS Hulk
const CICIDS2017_HULK_SAMPLE = {
  "Destination Port": 80,
  "Flow Duration": 1878,
  "Total Fwd Packets": 3,
  "Total Backward Packets": 6,
  "Total Length of Fwd Packets": 382,
  "Total Length of Bwd Packets": 11595,
  "Fwd Packet Length Max": 382,
  "Fwd Packet Length Min": 0,
  "Fwd Packet Length Mean": 127.333333,
  "Fwd Packet Length Std": 220.547803,
  "Bwd Packet Length Max": 4355,
  "Bwd Packet Length Min": 0,
  "Bwd Packet Length Mean": 1932.5,
  "Bwd Packet Length Std": 2182.468304,
  "Flow Bytes/s": 6377529.286,
  "Flow Packets/s": 4792.332268,
  "Flow IAT Mean": 234.75,
  "Flow IAT Std": 229.129876,
  "Flow IAT Max": 577,
  "Flow IAT Min": 15,
  "Fwd IAT Total": 975,
  "Fwd IAT Mean": 487.5,
  "Fwd IAT Std": 265.165043,
  "Fwd IAT Max": 675,
  "Fwd IAT Min": 300,
  "Bwd IAT Total": 1780,
  "Bwd IAT Mean": 356.0,
  "Bwd IAT Std": 399.788069,
  "Bwd IAT Max": 950,
  "Bwd IAT Min": 15,
  "Fwd PSH Flags": 0,
  "Bwd PSH Flags": 0,
  "Fwd URG Flags": 0,
  "Bwd URG Flags": 0,
  "Fwd Header Length": 104,
  "Bwd Header Length": 200,
  "Fwd Packets/s": 1597.444089,
  "Bwd Packets/s": 3194.888179,
  "Min Packet Length": 0,
  "Max Packet Length": 4355,
  "Packet Length Mean": 1197.7,
  "Packet Length Std": 1886.332364,
  "Packet Length Variance": 3558249.789,
  "FIN Flag Count": 0,
  "SYN Flag Count": 0,
  "RST Flag Count": 0,
  "PSH Flag Count": 1,
  "ACK Flag Count": 0,
  "URG Flag Count": 0,
  "CWE Flag Count": 0,
  "ECE Flag Count": 0,
  "Down/Up Ratio": 2,
  "Average Packet Size": 1330.777778,
  "Avg Fwd Segment Size": 127.333333,
  "Avg Bwd Segment Size": 1932.5,
  "Fwd Header Length.1": 104,
  "Fwd Avg Bytes/Bulk": 0,
  "Fwd Avg Packets/Bulk": 0,
  "Fwd Avg Bulk Rate": 0,
  "Bwd Avg Bytes/Bulk": 0,
  "Bwd Avg Packets/Bulk": 0,
  "Bwd Avg Bulk Rate": 0,
  "Subflow Fwd Packets": 3,
  "Subflow Fwd Bytes": 382,
  "Subflow Bwd Packets": 6,
  "Subflow Bwd Bytes": 11595,
  "Init_Win_bytes_forward": 29200,
  "Init_Win_bytes_backward": 235,
  "act_data_pkt_fwd": 1,
  "min_seg_size_forward": 32,
  "Active Mean": 0.0,
  "Active Std": 0.0,
  "Active Max": 0,
  "Active Min": 0,
  "Idle Mean": 0.0,
  "Idle Std": 0.0,
  "Idle Max": 0,
  "Idle Min": 0
};

const PredictPage = () => {
  const { role } = useAuth();
  const [datasetType, setDatasetType] = useState('nsl_kdd');
  const [inputJsonText, setInputJsonText] = useState(JSON.stringify(NSL_KDD_BENIGN_SAMPLE, null, 2));
  const [currentGroundTruth, setCurrentGroundTruth] = useState('Normal');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const handleDatasetChange = (type) => {
    setDatasetType(type);
    setResult(null);
    setError(null);
    if (type === 'nsl_kdd') {
      setInputJsonText(JSON.stringify(NSL_KDD_BENIGN_SAMPLE, null, 2));
      setCurrentGroundTruth('Normal');
    } else {
      setInputJsonText(JSON.stringify(CICIDS2017_BENIGN_SAMPLE, null, 2));
      setCurrentGroundTruth('BENIGN');
    }
  };

  const loadPreset = (presetKey) => {
    setResult(null);
    setError(null);
    if (datasetType === 'nsl_kdd') {
      if (presetKey === 'benign') {
        setInputJsonText(JSON.stringify(NSL_KDD_BENIGN_SAMPLE, null, 2));
        setCurrentGroundTruth('Normal');
      } else if (presetKey === 'dos') {
        setInputJsonText(JSON.stringify(NSL_KDD_DOS_SAMPLE, null, 2));
        setCurrentGroundTruth('DoS');
      } else if (presetKey === 'probe') {
        setInputJsonText(JSON.stringify(NSL_KDD_PROBE_SAMPLE, null, 2));
        setCurrentGroundTruth('Probe');
      } else if (presetKey === 'u2r') {
        setInputJsonText(JSON.stringify(NSL_KDD_U2R_SAMPLE, null, 2));
        setCurrentGroundTruth('U2R');
      }
    } else {
      if (presetKey === 'benign') {
        setInputJsonText(JSON.stringify(CICIDS2017_BENIGN_SAMPLE, null, 2));
        setCurrentGroundTruth('BENIGN');
      } else if (presetKey === 'ddos') {
        setInputJsonText(JSON.stringify(CICIDS2017_DDOS_SAMPLE, null, 2));
        setCurrentGroundTruth('DDoS');
      } else if (presetKey === 'hulk') {
        setInputJsonText(JSON.stringify(CICIDS2017_HULK_SAMPLE, null, 2));
        setCurrentGroundTruth('DoS Hulk');
      }
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setResult(null);

    let parsedData;
    try {
      parsedData = JSON.parse(inputJsonText);
    } catch (err) {
      setError('Invalid JSON payload syntax. Please check feature dictionary formatting.');
      setSubmitting(false);
      return;
    }

    try {
      const res = await submitPrediction({
        datasetType,
        inputData: parsedData,
        sourceInfo: currentGroundTruth ? { groundTruth: currentGroundTruth } : undefined
      });
      setResult(res);
    } catch (err) {
      setError(err.message || 'Failed to execute prediction request via backend.');
    } finally {
      setSubmitting(false);
    }
  };

  const firstPred = result?.predictions?.[0];

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Cpu size={22} style={{ color: 'var(--accent-cyan)' }} />
          Manual Intrusion Prediction Testing
        </h2>
        <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
          Test raw network feature payloads against the FastAPI XGBoost engine via Node.js Express backend
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(440px, 1fr))', gap: '1.5rem' }}>
        {/* Input Form Panel */}
        <div className="soc-card">
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Zap size={16} style={{ color: 'var(--accent-cyan)' }} />
            Inference Payload Config
          </h3>

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Target Dataset Schema:</label>
              <select
                value={datasetType}
                onChange={(e) => handleDatasetChange(e.target.value)}
                className="form-select"
              >
                <option value="nsl_kdd">NSL-KDD (37 Features)</option>
                <option value="cicids2017">CICIDS2017 (43 Features)</option>
              </select>
            </div>

            {datasetType === 'nsl_kdd' ? (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '1rem' }}>
                <button type="button" onClick={() => loadPreset('benign')} className="btn" style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}>
                  Load Benign (Normal)
                </button>
                <button type="button" onClick={() => loadPreset('dos')} className="btn" style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem', borderColor: 'rgba(244,63,94,0.4)', color: '#f87171' }}>
                  Load DoS (Neptune)
                </button>
                <button type="button" onClick={() => loadPreset('probe')} className="btn" style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem', borderColor: 'rgba(245,158,11,0.4)', color: '#fbbf24' }}>
                  Load Probe (Satan)
                </button>
                <button type="button" onClick={() => loadPreset('u2r')} className="btn" style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem', borderColor: 'rgba(168,85,247,0.4)', color: '#c084fc' }}>
                  Load U2R (Buffer Overflow)
                </button>
              </div>
            ) : (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '1rem' }}>
                <button type="button" onClick={() => loadPreset('benign')} className="btn" style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}>
                  Load Benign Sample
                </button>
                <button type="button" onClick={() => loadPreset('ddos')} className="btn" style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem', borderColor: 'rgba(244,63,94,0.4)', color: '#f87171' }}>
                  Load DDoS Attack Sample
                </button>
                <button type="button" onClick={() => loadPreset('hulk')} className="btn" style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem', borderColor: 'rgba(245,158,11,0.4)', color: '#fbbf24' }}>
                  Load DoS Hulk Attack Sample
                </button>
              </div>
            )}

            <div className="form-group">
              <label className="form-label">Raw Input Features (JSON Dict):</label>
              <textarea
                value={inputJsonText}
                onChange={(e) => setInputJsonText(e.target.value)}
                rows={14}
                className="form-input"
                style={{ fontFamily: 'var(--font-mono)', fontSize: '0.775rem', resize: 'vertical' }}
              />
            </div>

            {error && (
              <div style={{ background: 'rgba(244, 63, 94, 0.15)', border: '1px solid rgba(244, 63, 94, 0.3)', padding: '0.75rem', borderRadius: '8px', color: '#f87171', fontSize: '0.825rem', marginBottom: '1rem' }}>
                {error}
              </div>
            )}

            {role === 'VIEWER' ? (
              <div style={{ background: 'rgba(59, 130, 246, 0.12)', border: '1px solid rgba(59, 130, 246, 0.3)', padding: '0.75rem', borderRadius: '8px', color: '#60a5fa', fontSize: '0.825rem', textAlign: 'center' }}>
                Read-Only Role (VIEWER): Prediction submission requires ANALYST or ADMIN role.
              </div>
            ) : (
              <button type="submit" disabled={submitting} className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }}>
                <Send size={16} />
                {submitting ? 'Executing XGBoost Inference...' : 'Submit Prediction Request'}
              </button>
            )}
          </form>
        </div>

        {/* Output Results Panel */}
        <div className="soc-card">
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Layers size={16} style={{ color: 'var(--accent-purple)' }} />
            Inference Prediction Telemetry Output
          </h3>

          {submitting ? (
            <LoadingSpinner message="Communicating with Node.js -> FastAPI Docker XGBoost Pipeline..." />
          ) : !result ? (
            <div style={{ padding: '4rem 1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
              <Cpu size={40} style={{ color: 'var(--border-color)', marginBottom: '0.75rem' }} />
              <p style={{ fontSize: '0.9rem' }}>Submit a feature payload on the left to see live model classification output.</p>
            </div>
          ) : (
            <div>
              {/* Main Classification Callout */}
              {(() => {
                const isAttackTruth = currentGroundTruth && !['benign', 'normal'].includes(currentGroundTruth.toLowerCase());
                const isAttackPred = firstPred?.prediction && !['benign', 'normal'].includes(firstPred.prediction.toLowerCase());
                const isMatch = currentGroundTruth && (
                  currentGroundTruth.toLowerCase() === firstPred?.prediction?.toLowerCase() ||
                  (!isAttackTruth && !isAttackPred)
                );
                const isMissedAttack = isAttackTruth && !isAttackPred;

                return (
                  <>
                    <div style={{
                      background: isMissedAttack 
                        ? 'rgba(239, 68, 68, 0.2)' 
                        : result.alert_generated 
                          ? 'rgba(244, 63, 94, 0.15)' 
                          : 'rgba(16, 185, 129, 0.15)',
                      border: `1px solid ${isMissedAttack 
                        ? 'rgba(239, 68, 68, 0.6)' 
                        : result.alert_generated 
                          ? 'rgba(244, 63, 94, 0.4)' 
                          : 'rgba(16, 185, 129, 0.4)'}`,
                      padding: '1.25rem',
                      borderRadius: '10px',
                      marginBottom: '1.25rem',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      flexWrap: 'wrap',
                      gap: '1rem'
                    }}>
                      <div>
                        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.2rem', flexWrap: 'wrap' }}>
                          <span style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-secondary)' }}>
                            ML Prediction
                          </span>
                          {currentGroundTruth && (
                            <span style={{ fontSize: '0.7rem', background: 'rgba(59, 130, 246, 0.2)', border: '1px solid rgba(59, 130, 246, 0.4)', color: '#93c5fd', padding: '0.1rem 0.4rem', borderRadius: '4px' }}>
                              Ground Truth: {currentGroundTruth}
                            </span>
                          )}
                          {currentGroundTruth && (
                            isMatch ? (
                              <span style={{ fontSize: '0.7rem', background: 'rgba(16, 185, 129, 0.2)', border: '1px solid rgba(16, 185, 129, 0.4)', color: '#34d399', padding: '0.1rem 0.4rem', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                                <CheckCircle size={10} /> Prediction Matched
                              </span>
                            ) : isMissedAttack ? (
                              <span style={{ fontSize: '0.7rem', background: 'rgba(239, 68, 68, 0.25)', border: '1px solid rgba(239, 68, 68, 0.6)', color: '#fca5a5', padding: '0.1rem 0.4rem', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '0.2rem', fontWeight: 600 }}>
                                <XCircle size={10} /> Missed Attack (False Negative)
                              </span>
                            ) : (
                              <span style={{ fontSize: '0.7rem', background: 'rgba(245, 158, 11, 0.2)', border: '1px solid rgba(245, 158, 11, 0.4)', color: '#fcd34d', padding: '0.1rem 0.4rem', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                                <AlertTriangle size={10} /> Class Mismatch
                              </span>
                            )
                          )}
                        </div>
                        <div style={{ fontSize: '1.6rem', fontWeight: 800, color: isMissedAttack ? '#f87171' : result.alert_generated ? '#f87171' : '#34d399', margin: '0.2rem 0' }}>
                          {firstPred?.prediction}
                        </div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                          Model Version: {result.model_version}
                        </div>
                      </div>

                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>Confidence Score</div>
                        <div style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#fff' }}>
                          {(firstPred?.confidence * 100).toFixed(2)}%
                        </div>
                        <SeverityBadge isBenign={!result.alert_generated} severity={result.severity} prediction={firstPred?.prediction} />
                      </div>
                    </div>

                    {isMissedAttack && (
                      <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.4)', padding: '0.85rem', borderRadius: '8px', marginBottom: '1.25rem', color: '#fca5a5', fontSize: '0.825rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <XCircle size={16} style={{ flexShrink: 0 }} />
                        <span>
                          <strong>Missed Attack:</strong> Model classified ground-truth threat <strong>{currentGroundTruth}</strong> as <strong>{firstPred?.prediction}</strong>. This classification error is transparently reported and retained for model audit.
                        </span>
                      </div>
                    )}
                  </>
                );
              })()}

              {/* Alert Generation Info */}
              {result.alert_generated ? (
                <div style={{ background: 'rgba(245, 158, 11, 0.12)', border: '1px solid rgba(245, 158, 11, 0.3)', padding: '0.85rem', borderRadius: '8px', marginBottom: '1.25rem', color: '#fbbf24', fontSize: '0.825rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <AlertTriangle size={16} />
                  <span>Security Threat Alert automatically generated and logged in MongoDB queue (Alert ID: <code>{result.alert_id}</code>).</span>
                </div>
              ) : (
                <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.25)', padding: '0.85rem', borderRadius: '8px', marginBottom: '1.25rem', color: '#34d399', fontSize: '0.825rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <CheckCircle size={16} />
                  <span>Traffic classified as benign. Log persisted in MongoDB (Log ID: <code>{result.log_id}</code>).</span>
                </div>
              )}

              {/* Class Probabilities Distribution */}
              {firstPred?.class_probabilities && (
                <div>
                  <h4 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                    Class Probabilities Breakdown:
                  </h4>
                  <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                    {Object.entries(firstPred.class_probabilities).map(([cls, prob]) => (
                      <div key={cls} style={{ marginBottom: '0.6rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '0.2rem' }}>
                          <span style={{ color: cls === firstPred.prediction ? 'var(--accent-cyan)' : 'var(--text-secondary)', fontWeight: cls === firstPred.prediction ? 700 : 400 }}>{cls}</span>
                          <span style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>{(prob * 100).toFixed(2)}%</span>
                        </div>
                        <div style={{ height: '6px', background: '#1e293b', borderRadius: '3px', overflow: 'hidden' }}>
                          <div style={{
                            height: '100%',
                            width: `${(prob * 100).toFixed(2)}%`,
                            background: cls === firstPred.prediction ? (result.alert_generated ? '#f43f5e' : '#10b981') : '#38bdf8',
                            transition: 'width 0.4s ease'
                          }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PredictPage;
