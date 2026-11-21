const metricsCollector = require('../utils/metricsCollector');

exports.getMetricsJSON = (req, res) => {
  const summary = metricsCollector.getMetricsSummary();
  res.status(200).json({
    success: true,
    data: summary
  });
};

exports.getMetricsPrometheus = (req, res) => {
  const text = metricsCollector.getPrometheusFormat();
  res.setHeader('Content-Type', 'text/plain; version=0.0.4');
  res.status(200).send(text);
};
