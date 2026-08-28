package veremivndn.ids.features;

//
// FeatureExtractor for VeReMiVNDN-EXE.
//
// Defaults are set for the EXE multi-plane benchmark: 50 ms sampling,
// 5 s sliding window, and a 110-dimensional feature vector composed of
// the original 87 dimensions plus 23 new dimensions split across five
// MI-IDS plane categories. Set extractionInterval=100ms and
// enableExePlaneFeatures=false to fall back to the published 87-dim mode.
//
simple FeatureExtractor
{
    parameters:
        @class(veremivndn::FeatureExtractor);
        @display("i=block/table");

        // ---- Original (published VeReMiVNDN) controls ----
        double extractionInterval @unit(s) = default(50ms);
        double timeWindowSize     @unit(s) = default(5s);
        int    maxHistorySize              = default(200);
        bool   enableRealTimeExtraction    = default(true);

        // ---- New EXE plane-specific feature toggles ----
        // When true, the extractor emits the 23 additional features that the
        // five MI-IDS detectors need (Section IV/V of the EXE manuscript).
        bool   enableExePlaneFeatures      = default(true);

        // Signature / trust plane (Content Poisoning detector)
        bool   enableSignatureFeatures     = default(true);
        double payloadEntropyWindow @unit(s) = default(1s);

        // Cache side-channel plane (Cache Pollution + Privacy Leakage)
        bool   enableCacheSideChannelFeatures = default(true);
        int    cacheTimingHistogramBins       = default(32);

        // Identity / graph plane (Sybil Amplification)
        bool   enableIdentityGraphFeatures = default(true);
        double interactionGraphWindow @unit(s) = default(2s);
        // Co-location radius (m) used to detect several signed identities
        // transmitting from the same point, the geometric Sybil signature.
        double sybilPositionEpsilon        = default(25.0);

        // Per-tick labelled export of the five plane vectors. One file per
        // observer; the label column is post-hoc ground truth and is never an
        // input to the detectors. Empty string disables the export.
        string planeFeatureCsv             = default("");

        // Forwarding-behavior plane (Selective Forwarding)
        bool   enableForwardingBehaviorFeatures = default(true);
        int    perFlowDropHistorySize           = default(64);

        // PHY link-quality plane (Radio Jamming)
        bool   enablePhyLinkQualityFeatures = default(true);
        double phyRollingWindow @unit(s)    = default(0.5s);

        // ---- Signals ----
        @signal[featureExtraction](type=long);
        @signal[anomalyScore](type=double);
        @signal[featureVectorDim](type=long);

        // Per-plane scalar exports (consumed by MI-IDS detectors)
        @signal[planeScoreData](type=double);
        @signal[planeScoreCache](type=double);
        @signal[planeScoreTrust](type=double);
        @signal[planeScoreForwarding](type=double);
        @signal[planeScorePhy](type=double);

        @statistic[featureExtraction](title="Feature Extractions"; record=count,vector);
        @statistic[anomalyScore](title="Anomaly Score"; record=stats,vector);
        @statistic[featureVectorDim](title="Feature Vector Dim"; record=last);
        @statistic[planeScoreData](title="Data-plane anomaly score"; record=stats,vector);
        @statistic[planeScoreCache](title="Cache-plane anomaly score"; record=stats,vector);
        @statistic[planeScoreTrust](title="Trust-plane anomaly score"; record=stats,vector);
        @statistic[planeScoreForwarding](title="Forwarding-behavior anomaly score"; record=stats,vector);
        @statistic[planeScorePhy](title="PHY-plane anomaly score"; record=stats,vector);

    gates:
        input ndnIn @labels(NdnPacket);
        output ndnOut @labels(NdnPacket);
}
