/**
 * Prediction Controller
 * Handles POST /api/predictions (IPC to FastAPI -> Log save -> Alert generation -> Response)
 * and GET /api/predictions (Paginated & filtered log retrieval).
 */

const Log = require('../models/Log');
const Alert = require('../models/Alert');
const mlService = require('../services/mlService');
const { validatePredictionInput } = require('../validators/predictionValidator');
const { mapPredictionToSeverity } = require('../utils/severityMapper');
const { publishPredictionCreated, publishAlertCreated, publishMetricsUpdated } = require('../realtime/eventPublisher');
const correlationEngine = require('../services/correlationEngine');
const settingsService = require('../services/settingsService');
const notificationService = require('../services/notificationService');
const { resolveNetworkSourceInfo } = require('../utils/originResolver');
const logger = require('../utils/logger');

const createPrediction = async (req, res, next) => {
  try {
    const validated = validatePredictionInput(req.body);
    const { datasetType, inputData, sourceInfo } = validated;

    // 1. Call FastAPI ML service
    const mlResult = await mlService.predict(datasetType, inputData, req.requestId);

    const firstPred = mlResult.predictions[0];
    const predictionLabel = firstPred.prediction;
    const confidence = firstPred.confidence;
    const predictionIndex = firstPred.prediction_index;
    const classProbabilities = firstPred.class_probabilities || {};
    const modelVersion = mlResult.model_version;
    const recordsProcessed = mlResult.records_processed || 1;
    const latencyMs = mlResult.client_latency_ms || 0;

    // Resolve and enrich canonical network metadata from sourceInfo and inputData
    const enrichedSourceInfo = resolveNetworkSourceInfo(sourceInfo, inputData);

    // 2. Persist threat log in MongoDB
    const logDoc = new Log({
      timestamp: new Date(),
      datasetType,
      prediction: predictionLabel,
      predictionIndex,
      confidence,
      modelVersion,
      recordsProcessed,
      classProbabilities,
      processingLatencyMs: latencyMs,
      sourceInfo: enrichedSourceInfo || null
    });
    await logDoc.save();

    // 3. Evaluate threat severity and generate Alert if malicious
    const severityInfo = mapPredictionToSeverity(datasetType, predictionLabel);
    let alertCreated = false;
    let alertDoc = null;

    if (severityInfo.isAttack) {
      // Dynamic alert threshold confidence evaluation
      const thresholdSetting = await settingsService.getSetting('alertThresholdConfidence', 80);
      const normThreshold = Number(thresholdSetting) > 1 ? Number(thresholdSetting) / 100 : Number(thresholdSetting);

      let finalSeverity = severityInfo.severity;
      let finalDescription = severityInfo.description;

      // If policy severity is HIGH, verify whether model confidence reaches the required threshold
      if (finalSeverity === 'high' && confidence < normThreshold) {
        finalSeverity = 'medium';
        finalDescription += ` (Demoted from HIGH to MEDIUM: model confidence ${(confidence * 100).toFixed(2)}% below threshold ${(normThreshold * 100).toFixed(0)}%)`;
      }

      alertDoc = new Alert({
        timestamp: new Date(),
        severity: finalSeverity,
        attackType: severityInfo.attackType,
        prediction: predictionLabel,
        confidence,
        datasetType,
        modelVersion,
        status: 'open',
        description: finalDescription,
        sourceInfo: enrichedSourceInfo || null
      });
      await alertDoc.save();
      alertCreated = true;
      logger.warn(`[Alert Generated] Threat detected: ${predictionLabel} (${finalSeverity.toUpperCase()}) on ${datasetType}`);

      // Forward to multi-signal correlation engine
      const srcIp = sourceInfo?.src_ip || inputData?.src_ip || inputData?.['Source IP'] || 'unknown';
      const dstIp = sourceInfo?.dst_ip || inputData?.dst_ip || inputData?.['Destination IP'] || 'unknown';
      correlationEngine.ingestAndCorrelate({
        source: 'ml',
        src_ip: srcIp,
        dst_ip: dstIp,
        prediction: predictionLabel,
        confidence,
        severity: finalSeverity
      }).catch(err => logger.error('[Correlation Engine Error]', err));
    } else {
      // 3b. Benign traffic resumption check for enableAutoResolution
      const autoResolveEnabled = await settingsService.getSetting('enableAutoResolution', false);
      if (autoResolveEnabled) {
        const flowId = sourceInfo?.flow_id || sourceInfo?.flowId || inputData?.flow_id || inputData?.flowId;
        const srcIp = sourceInfo?.src_ip || sourceInfo?.['Source IP'] || inputData?.src_ip || inputData?.['Source IP'];
        const dstIp = sourceInfo?.dst_ip || sourceInfo?.['Destination IP'] || inputData?.dst_ip || inputData?.['Destination IP'];
        const srcPort = sourceInfo?.src_port !== undefined ? sourceInfo.src_port : (sourceInfo?.['Source Port'] !== undefined ? sourceInfo['Source Port'] : (inputData?.src_port !== undefined ? inputData.src_port : inputData?.['Source Port']));
        const dstPort = sourceInfo?.dst_port !== undefined ? sourceInfo.dst_port : (sourceInfo?.['Destination Port'] !== undefined ? sourceInfo['Destination Port'] : (inputData?.dst_port !== undefined ? inputData.dst_port : inputData?.['Destination Port']));
        const protocol = sourceInfo?.protocol || sourceInfo?.['Protocol'] || inputData?.protocol || inputData?.['Protocol'] || inputData?.protocol_type;

        let query = null;

        // 1. PRIMARY PRECEDENCE: Exact flow_id correlation
        // If an incoming benign flow has a valid flow_id, ONLY alerts with the exact same flow_id may resolve.
        // It must never fall back to 5-tuple matching if flow_id is specified.
        if (flowId) {
          query = {
            datasetType,
            status: { $in: ['open', 'acknowledged'] },
            $or: [
              { 'sourceInfo.flow_id': flowId },
              { 'sourceInfo.flowId': flowId }
            ]
          };
        }
        // 2. FALLBACK PRECEDENCE: True Complete 5-Tuple Correlation
        // If and ONLY IF flow_id is unavailable, all 5 values must be present and valid:
        // 1) src_ip, 2) dst_ip, 3) src_port, 4) dst_port, 5) protocol.
        // Partial tuples (e.g. missing src_port, missing protocol) are strictly REJECTED.
        else {
          const hasComplete5Tuple = (
            Boolean(srcIp) && srcIp !== 'unknown' &&
            Boolean(dstIp) && dstIp !== 'unknown' &&
            srcPort !== undefined && srcPort !== null && srcPort !== '' && !isNaN(Number(srcPort)) && Number(srcPort) >= 0 && Number(srcPort) <= 65535 &&
            dstPort !== undefined && dstPort !== null && dstPort !== '' && !isNaN(Number(dstPort)) && Number(dstPort) >= 0 && Number(dstPort) <= 65535 &&
            Boolean(protocol) && protocol !== 'unknown'
          );

          if (hasComplete5Tuple) {
            const numSrcPort = Number(srcPort);
            const numDstPort = Number(dstPort);
            const protoStr = String(protocol).toLowerCase();

            query = {
              datasetType,
              status: { $in: ['open', 'acknowledged'] },
              $and: [
                {
                  $or: [
                    { 'sourceInfo.src_ip': srcIp },
                    { 'sourceInfo.Source IP': srcIp }
                  ]
                },
                {
                  $or: [
                    { 'sourceInfo.dst_ip': dstIp },
                    { 'sourceInfo.Destination IP': dstIp }
                  ]
                },
                {
                  $or: [
                    { 'sourceInfo.src_port': numSrcPort },
                    { 'sourceInfo.src_port': String(numSrcPort) },
                    { 'sourceInfo.Source Port': numSrcPort },
                    { 'sourceInfo.Source Port': String(numSrcPort) }
                  ]
                },
                {
                  $or: [
                    { 'sourceInfo.dst_port': numDstPort },
                    { 'sourceInfo.dst_port': String(numDstPort) },
                    { 'sourceInfo.Destination Port': numDstPort },
                    { 'sourceInfo.Destination Port': String(numDstPort) }
                  ]
                },
                {
                  $or: [
                    { 'sourceInfo.protocol': protocol },
                    { 'sourceInfo.protocol': protoStr },
                    { 'sourceInfo.Protocol': protocol },
                    { 'sourceInfo.Protocol': protoStr }
                  ]
                }
              ]
            };
          } else {
            // 3. INSUFFICIENT CORRELATION IDENTITY:
            // src_ip alone or partial tuples (e.g. missing src_port or protocol) are strictly rejected
            logger.debug(`[Auto-Resolution] Benign flow lacks exact flow_id and lacks complete 5-tuple (src_ip=${srcIp || 'missing'}, dst_ip=${dstIp || 'missing'}, src_port=${srcPort !== undefined ? srcPort : 'missing'}, dst_port=${dstPort !== undefined ? dstPort : 'missing'}, protocol=${protocol || 'missing'}). Skipping auto-resolution to preserve alert safety.`);
          }
        }

        if (query) {
          const matchingAlert = await Alert.findOne(query).sort({ timestamp: -1 });
          if (matchingAlert) {
            matchingAlert.status = 'resolved';
            matchingAlert.resolvedAt = new Date();
            const resolutionLabel = flowId ? `flow ${flowId}` : `5-tuple ${srcIp}:${srcPort}->${dstIp}:${dstPort}(${protocol})`;
            matchingAlert.description += ` [Auto-resolved: benign traffic resumed for ${resolutionLabel}]`;
            await matchingAlert.save();
            logger.info(`[Auto-Resolution] Alert ${matchingAlert._id} (${matchingAlert.attackType}) automatically resolved for ${resolutionLabel}`);
            
            const reqId = req.id || req.headers['x-request-id'];
            publishAlertCreated({
              id: matchingAlert._id,
              timestamp: matchingAlert.timestamp,
              severity: matchingAlert.severity,
              attackType: matchingAlert.attackType,
              prediction: matchingAlert.prediction,
              confidence: matchingAlert.confidence,
              datasetType: matchingAlert.datasetType,
              modelVersion: matchingAlert.modelVersion,
              status: matchingAlert.status,
              description: matchingAlert.description,
              sourceInfo: matchingAlert.sourceInfo,
              resolvedAt: matchingAlert.resolvedAt
            }, reqId);
          }
        }
      }
    }

    // 4. Broadcast Real-Time Events
    const reqId = req.id || req.headers['x-request-id'];
    publishPredictionCreated({
      id: logDoc._id,
      timestamp: logDoc.timestamp,
      datasetType: logDoc.datasetType,
      prediction: logDoc.prediction,
      predictionIndex: logDoc.predictionIndex,
      confidence: logDoc.confidence,
      modelVersion: logDoc.modelVersion,
      processingLatencyMs: logDoc.processingLatencyMs,
      sourceInfo: logDoc.sourceInfo
    }, reqId);

    if (alertCreated && alertDoc) {
      publishAlertCreated({
        id: alertDoc._id,
        timestamp: alertDoc.timestamp,
        severity: alertDoc.severity,
        attackType: alertDoc.attackType,
        prediction: alertDoc.prediction,
        confidence: alertDoc.confidence,
        datasetType: alertDoc.datasetType,
        modelVersion: alertDoc.modelVersion,
        status: alertDoc.status,
        description: alertDoc.description,
        sourceInfo: alertDoc.sourceInfo
      }, reqId);

      // Phase 20.9: Automated email notification for newly created HIGH / CRITICAL alerts
      if (alertDoc.severity === 'high' || alertDoc.severity === 'critical') {
        notificationService.sendSecurityAlertNotification(alertDoc).catch((err) => {
          logger.error?.('[Notification Service] Automated security alert email delivery failed:', err?.message || err);
        });
      }
    }

    // 5. Formulate response payload
    res.status(200).json({
      success: true,
      log_id: logDoc._id,
      dataset_type: datasetType,
      model_version: modelVersion,
      records_processed: recordsProcessed,
      predictions: mlResult.predictions,
      alert_generated: alertCreated,
      alert_id: alertDoc ? alertDoc._id : null,
      severity: alertDoc ? alertDoc.severity : null
    });
  } catch (error) {
    next(error);
  }
};

const getPredictions = async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '20', 10)));
    const skip = (page - 1) * limit;

    const filter = {};

    if (req.query.datasetType) {
      filter.datasetType = req.query.datasetType;
    }

    if (req.query.prediction) {
      filter.prediction = req.query.prediction;
    }

    if (req.query.startDate || req.query.endDate) {
      filter.timestamp = {};
      if (req.query.startDate) {
        filter.timestamp.$gte = new Date(req.query.startDate);
      }
      if (req.query.endDate) {
        filter.timestamp.$lte = new Date(req.query.endDate);
      }
    }

    const [total, data] = await Promise.all([
      Log.countDocuments(filter),
      Log.find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).lean()
    ]);

    const totalPages = Math.ceil(total / limit) || 1;

    res.status(200).json({
      success: true,
      pagination: {
        total,
        page,
        limit,
        totalPages
      },
      data
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createPrediction,
  getPredictions
};
