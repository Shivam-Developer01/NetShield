const Log = require('../models/Log');
const Alert = require('../models/Alert');

const BENIGN_LABELS = ['Normal', 'BENIGN'];

const buildDateAndDatasetFilter = (query = {}) => {
  const filter = {};
  if (query.datasetType && query.datasetType !== 'all') {
    filter.datasetType = query.datasetType;
  }
  if (query.startDate || query.endDate) {
    filter.timestamp = {};
    if (query.startDate) filter.timestamp.$gte = new Date(query.startDate);
    if (query.endDate) filter.timestamp.$lte = new Date(query.endDate);
  }
  return filter;
};

const getOverview = async (query = {}) => {
  const logFilter = buildDateAndDatasetFilter(query);
  const alertFilter = buildDateAndDatasetFilter(query);

  const [logStats] = await Log.aggregate([
    { $match: logFilter },
    {
      $group: {
        _id: null,
        totalPredictions: { $sum: 1 },
        benignPredictions: {
          $sum: { $cond: [{ $in: ['$prediction', BENIGN_LABELS] }, 1, 0] }
        },
        maliciousPredictions: {
          $sum: { $cond: [{ $not: [{ $in: ['$prediction', BENIGN_LABELS] }] }, 1, 0] }
        },
        avgConfidence: { $avg: '$confidence' },
        avgLatency: { $avg: '$processingLatencyMs' }
      }
    }
  ]);

  const [alertStats] = await Alert.aggregate([
    { $match: alertFilter },
    {
      $group: {
        _id: null,
        activeAlerts: { $sum: { $cond: [{ $eq: ['$status', 'open'] }, 1, 0] } },
        criticalAlerts: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
        highAlerts: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } },
        mediumAlerts: { $sum: { $cond: [{ $eq: ['$severity', 'medium'] }, 1, 0] } },
        lowAlerts: { $sum: { $cond: [{ $eq: ['$severity', 'low'] }, 1, 0] } }
      }
    }
  ]);

  // Top Attack Type
  const [topAttack] = await Log.aggregate([
    { $match: { ...logFilter, prediction: { $nin: BENIGN_LABELS } } },
    { $group: { _id: '$prediction', count: { $sum: 1 } } },
    { $sort: { count: -1 } },
    { $limit: 1 }
  ]);

  // Top Dataset
  const [topDatasetRes] = await Log.aggregate([
    { $match: logFilter },
    { $group: { _id: '$datasetType', count: { $sum: 1 } } },
    { $sort: { count: -1 } },
    { $limit: 1 }
  ]);

  // Recent Threat Count (Last 24 Hours)
  const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const recentThreatCount = await Log.countDocuments({
    ...logFilter,
    prediction: { $nin: BENIGN_LABELS },
    timestamp: { $gte: twentyFourHoursAgo }
  });

  const total = logStats?.totalPredictions || 0;
  const benign = logStats?.benignPredictions || 0;
  const malicious = logStats?.maliciousPredictions || 0;
  const detectionRate = total > 0 ? Number(((malicious / total) * 100).toFixed(2)) : 0;
  const averageConfidence = logStats?.avgConfidence ? Number(logStats.avgConfidence.toFixed(2)) : 0;
  const averageProcessingLatencyMs = logStats?.avgLatency ? Number(logStats.avgLatency.toFixed(1)) : 0;

  return {
    totalPredictions: total,
    benignPredictions: benign,
    maliciousPredictions: malicious,
    activeAlerts: alertStats?.activeAlerts || 0,
    criticalAlerts: alertStats?.criticalAlerts || 0,
    highAlerts: alertStats?.highAlerts || 0,
    mediumAlerts: alertStats?.mediumAlerts || 0,
    lowAlerts: alertStats?.lowAlerts || 0,
    detectionRate,
    averageConfidence,
    averageProcessingLatencyMs,
    topAttackType: topAttack ? topAttack._id : 'None',
    topDataset: topDatasetRes ? topDatasetRes._id : (query.datasetType || 'nsl_kdd'),
    recentThreatCount
  };
};

const getTrends = async (query = {}) => {
  const logFilter = buildDateAndDatasetFilter(query);
  const alertFilter = buildDateAndDatasetFilter(query);
  const interval = query.interval || 'day';

  let formatStr = '%Y-%m-%d';
  if (interval === 'hour') formatStr = '%Y-%m-%dT%H:00:00';
  else if (interval === 'week') formatStr = '%G-W%V';

  const logSeries = await Log.aggregate([
    { $match: logFilter },
    {
      $group: {
        _id: { $dateToString: { format: formatStr, date: '$timestamp' } },
        total: { $sum: 1 },
        benign: { $sum: { $cond: [{ $in: ['$prediction', BENIGN_LABELS] }, 1, 0] } },
        malicious: { $sum: { $cond: [{ $not: [{ $in: ['$prediction', BENIGN_LABELS] }] }, 1, 0] } }
      }
    },
    { $sort: { _id: 1 } }
  ]);

  const alertSeries = await Alert.aggregate([
    { $match: alertFilter },
    {
      $group: {
        _id: { $dateToString: { format: formatStr, date: '$timestamp' } },
        alerts: { $sum: 1 }
      }
    }
  ]);

  const alertMap = new Map(alertSeries.map(item => [item._id, item.alerts]));

  const data = logSeries.map(item => ({
    timestamp: item._id,
    total: item.total,
    benign: item.benign,
    malicious: item.malicious,
    alerts: alertMap.get(item._id) || 0
  }));

  return {
    interval,
    data
  };
};

const getAttacks = async (query = {}) => {
  const filter = buildDateAndDatasetFilter(query);
  filter.prediction = { $nin: BENIGN_LABELS };

  const attackAgg = await Log.aggregate([
    { $match: filter },
    {
      $group: {
        _id: '$prediction',
        count: { $sum: 1 },
        avgConfidence: { $avg: '$confidence' }
      }
    },
    { $sort: { count: -1 } }
  ]);

  const totalMalicious = attackAgg.reduce((sum, a) => sum + a.count, 0);

  // Map attack types to default severities
  const severityMap = {
    neptune: 'high',
    smurf: 'high',
    pod: 'medium',
    teardrop: 'medium',
    land: 'medium',
    back: 'high',
    satan: 'high',
    ipsweep: 'medium',
    portsweep: 'medium',
    nmap: 'medium',
    guess_passwd: 'critical',
    ftp_write: 'high',
    multihop: 'critical',
    phf: 'high',
    spy: 'high',
    warezclient: 'medium',
    warezmaster: 'high',
    buffer_overflow: 'critical',
    loadmodule: 'critical',
    rootkit: 'critical',
    perl: 'critical',
    'DoS Attacks-Hulk': 'high',
    'PortScan': 'medium',
    'DDoS': 'high',
    'DoS GoldenEye': 'high',
    'FTP-Patator': 'high',
    'SSH-Patator': 'high',
    'DoS slowloris': 'medium',
    'DoS Slowhttptest': 'medium',
    'Bot': 'high',
    'Web Attack-Brute Force': 'high',
    'Web Attack-XSS': 'high',
    'Infiltration': 'critical',
    'Web Attack-Sql Injection': 'critical',
    'Heartbleed': 'critical'
  };

  return attackAgg.map(item => ({
    attackType: item._id,
    count: item.count,
    percentage: totalMalicious > 0 ? Number(((item.count / totalMalicious) * 100).toFixed(1)) : 0,
    averageConfidence: Number(item.avgConfidence.toFixed(2)),
    severity: severityMap[item._id] || 'high'
  }));
};

const getSeverity = async (query = {}) => {
  const logFilter = buildDateAndDatasetFilter(query);
  const alertFilter = buildDateAndDatasetFilter(query);

  const benignCount = await Log.countDocuments({ ...logFilter, prediction: { $in: BENIGN_LABELS } });

  const alertSeverities = await Alert.aggregate([
    { $match: alertFilter },
    { $group: { _id: '$severity', count: { $sum: 1 } } }
  ]);

  const sevMap = { low: 0, medium: 0, high: 0, critical: 0 };
  alertSeverities.forEach(s => {
    if (sevMap[s._id] !== undefined) {
      sevMap[s._id] = s.count;
    }
  });

  const grandTotal = benignCount + sevMap.low + sevMap.medium + sevMap.high + sevMap.critical;

  const calcPct = (cnt) => (grandTotal > 0 ? Number(((cnt / grandTotal) * 100).toFixed(1)) : 0);

  return {
    benign: { count: benignCount, percentage: calcPct(benignCount) },
    low: { count: sevMap.low, percentage: calcPct(sevMap.low) },
    medium: { count: sevMap.medium, percentage: calcPct(sevMap.medium) },
    high: { count: sevMap.high, percentage: calcPct(sevMap.high) },
    critical: { count: sevMap.critical, percentage: calcPct(sevMap.critical) },
    grandTotal
  };
};

const getModels = async (query = {}) => {
  const datasets = ['nsl_kdd', 'cicids2017'];
  const results = [];

  for (const ds of datasets) {
    const filter = { ...buildDateAndDatasetFilter(query), datasetType: ds };

    const [stats] = await Log.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$modelVersion',
          total: { $sum: 1 },
          benign: { $sum: { $cond: [{ $in: ['$prediction', BENIGN_LABELS] }, 1, 0] } },
          malicious: { $sum: { $cond: [{ $not: [{ $in: ['$prediction', BENIGN_LABELS] }] }, 1, 0] } },
          avgConfidence: { $avg: '$confidence' },
          avgLatency: { $avg: '$processingLatencyMs' }
        }
      }
    ]);

    const total = stats?.total || 0;
    const malicious = stats?.malicious || 0;
    const benign = stats?.benign || 0;

    results.push({
      datasetType: ds,
      modelVersion: stats?._id || (ds === 'nsl_kdd' ? 'NetShield-NSLKDD-XGBoost-v1.0' : 'NetShield-CICIDS2017-XGBoost-v1.0'),
      predictionCount: total,
      maliciousCount: malicious,
      benignCount: benign,
      detectionRate: total > 0 ? Number(((malicious / total) * 100).toFixed(2)) : 0,
      averageConfidence: stats?.avgConfidence ? Number(stats.avgConfidence.toFixed(2)) : 0,
      averageLatency: stats?.avgLatency ? Number(stats.avgLatency.toFixed(1)) : 0
    });
  }

  return results;
};

const getAlertAnalytics = async (query = {}) => {
  const filter = buildDateAndDatasetFilter(query);

  const [stats] = await Alert.aggregate([
    { $match: filter },
    {
      $group: {
        _id: null,
        totalAlerts: { $sum: 1 },
        openAlerts: { $sum: { $cond: [{ $eq: ['$status', 'open'] }, 1, 0] } },
        acknowledgedAlerts: { $sum: { $cond: [{ $eq: ['$status', 'acknowledged'] }, 1, 0] } },
        resolvedAlerts: { $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] } },
        criticalOpenAlerts: {
          $sum: { $cond: [{ $and: [{ $eq: ['$status', 'open'] }, { $eq: ['$severity', 'critical'] }] }, 1, 0] }
        },
        highOpenAlerts: {
          $sum: { $cond: [{ $and: [{ $eq: ['$status', 'open'] }, { $eq: ['$severity', 'high'] }] }, 1, 0] }
        }
      }
    }
  ]);

  // Average Time to Acknowledgement
  const [ackTiming] = await Alert.aggregate([
    { $match: { ...filter, acknowledgedAt: { $ne: null } } },
    {
      $project: {
        diffMs: { $subtract: ['$acknowledgedAt', '$timestamp'] }
      }
    },
    {
      $group: {
        _id: null,
        avgMs: { $avg: '$diffMs' },
        count: { $sum: 1 }
      }
    }
  ]);

  // Average Time to Resolution
  const [resolveTiming] = await Alert.aggregate([
    { $match: { ...filter, resolvedAt: { $ne: null } } },
    {
      $project: {
        diffMs: { $subtract: ['$resolvedAt', '$timestamp'] }
      }
    },
    {
      $group: {
        _id: null,
        avgMs: { $avg: '$diffMs' },
        count: { $sum: 1 }
      }
    }
  ]);

  return {
    totalAlerts: stats?.totalAlerts || 0,
    openAlerts: stats?.openAlerts || 0,
    acknowledgedAlerts: stats?.acknowledgedAlerts || 0,
    resolvedAlerts: stats?.resolvedAlerts || 0,
    criticalOpenAlerts: stats?.criticalOpenAlerts || 0,
    highOpenAlerts: stats?.highOpenAlerts || 0,
    averageTimeToAckMs: ackTiming && ackTiming.count > 0 ? Math.round(ackTiming.avgMs) : null,
    averageTimeToResolutionMs: resolveTiming && resolveTiming.count > 0 ? Math.round(resolveTiming.avgMs) : null
  };
};

const exportData = async (query = {}) => {
  const limit = Math.min(query.limit || 1000, 5000);
  const filter = buildDateAndDatasetFilter(query);

  const sanitizeCsvValue = (val) => {
    if (val === null || val === undefined) return '""';
    let str = String(val);
    if (/^[=+\-@\t\r]/.test(str)) {
      str = "'" + str;
    }
    return `"${str.replace(/"/g, '""')}"`;
  };

  if (query.type === 'alerts') {
    if (query.severity) filter.severity = query.severity;
    const alerts = await Alert.find(filter).sort({ timestamp: -1 }).limit(limit).lean();

    let csv = 'Alert ID,Timestamp,Severity,Attack Type,Prediction,Confidence,Dataset,Status,Acknowledged At,Resolved At\n';
    alerts.forEach(a => {
      csv += `${sanitizeCsvValue(a._id)},${sanitizeCsvValue(a.timestamp ? a.timestamp.toISOString() : '')},${sanitizeCsvValue(a.severity)},${sanitizeCsvValue(a.attackType)},${sanitizeCsvValue(a.prediction)},${a.confidence},${sanitizeCsvValue(a.datasetType)},${sanitizeCsvValue(a.status)},${sanitizeCsvValue(a.acknowledgedAt ? a.acknowledgedAt.toISOString() : '')},${sanitizeCsvValue(a.resolvedAt ? a.resolvedAt.toISOString() : '')}\n`;
    });
    return csv;
  } else if (query.type === 'predictions') {
    if (query.prediction) filter.prediction = query.prediction;
    const logs = await Log.find(filter).sort({ timestamp: -1 }).limit(limit).lean();

    let csv = 'Log ID,Timestamp,Dataset,Prediction,Confidence,Model Version,Records Processed,Latency Ms\n';
    logs.forEach(l => {
      csv += `${sanitizeCsvValue(l._id)},${sanitizeCsvValue(l.timestamp ? l.timestamp.toISOString() : '')},${sanitizeCsvValue(l.datasetType)},${sanitizeCsvValue(l.prediction)},${l.confidence},${sanitizeCsvValue(l.modelVersion)},${l.recordsProcessed || 1},${l.processingLatencyMs || 0}\n`;
    });
    return csv;
  } else {
    // Summary analytics export
    const overview = await getOverview(query);
    const attacks = await getAttacks(query);

    let csv = 'Metric,Value\n';
    csv += `Total Predictions,${overview.totalPredictions}\n`;
    csv += `Benign Predictions,${overview.benignPredictions}\n`;
    csv += `Malicious Predictions,${overview.maliciousPredictions}\n`;
    csv += `Detection Rate (%),${overview.detectionRate}\n`;
    csv += `Active Alerts,${overview.activeAlerts}\n`;
    csv += `Critical Alerts,${overview.criticalAlerts}\n`;
    csv += `Average Confidence,${overview.averageConfidence}\n`;
    csv += `Average Processing Latency (ms),${overview.averageProcessingLatencyMs}\n`;
    csv += `Top Attack Type,${sanitizeCsvValue(overview.topAttackType)}\n\n`;
    csv += 'Attack Type,Count,Percentage (%),Average Confidence,Severity\n';
    attacks.forEach(a => {
      csv += `${sanitizeCsvValue(a.attackType)},${a.count},${a.percentage},${a.averageConfidence},${sanitizeCsvValue(a.severity)}\n`;
    });
    return csv;
  }
};

module.exports = {
  getOverview,
  getTrends,
  getAttacks,
  getSeverity,
  getModels,
  getAlertAnalytics,
  exportData
};
