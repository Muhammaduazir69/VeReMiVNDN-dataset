//
// DP-IDS-VNDN - Main Controller Implementation
// Four-stage pipeline: telemetry -> scoring -> fusion -> penalisation
// Plus: ground truth collection, metrics feeding, extended monitoring
//

#include "DPIDSController.h"
#include "../features/ForwardingPlaneFeatureExtractor.h"
#include "../detectors/BehaviouralDetector.h"
#include "../detectors/ForwardingPlaneDetector.h"
#include "../fusion/DSFusionEngine.h"
#include "../strategy/AdaptiveForwardingStrategy.h"
#include "../evaluation/DPIDSMetrics.h"
#include "../../attacks/AttackBase.h"

namespace veremivndn {

Define_Module(DPIDSController);

DPIDSController::~DPIDSController() {
    cancelAndDelete(orchestrationTimer);
}

void DPIDSController::initialize(int stage) {
    if (stage == 0) {
        orchestrationInterval = par("orchestrationInterval").doubleValue();
        beliefThreshold = par("beliefThreshold");
        enablePenalization = par("enablePenalization");

        if (hasPar("enableExtendedMonitoring"))
            enableExtendedMonitoring = par("enableExtendedMonitoring");
        if (hasPar("extendedMonitoringDuration"))
            extendedMonitoringDuration = par("extendedMonitoringDuration").doubleValue();

        vehiclesMonitoredSignal = registerSignal("vehiclesMonitored");
        vehiclesDetectedSignal = registerSignal("vehiclesDetected");
        vehiclesPenalizedSignal = registerSignal("vehiclesPenalized");

        // Make key variables inspectable in Qtenv
        WATCH(totalDetections);
        WATCH(totalPenalizations);
        WATCH(currentMonitored);
        WATCH(currentDetected);
        WATCH(maxBeliefThisCycle);
        WATCH(beliefThreshold);
    }

    if (stage == 2) {
        // Get references to sibling submodules
        cModule *parent = getParentModule();
        featureExtractor = dynamic_cast<ForwardingPlaneFeatureExtractor*>(
            parent->getSubmodule("fpFeatureExtractor"));
        behaviouralDetector = dynamic_cast<BehaviouralDetector*>(
            parent->getSubmodule("behaviouralDetector"));
        forwardingDetector = dynamic_cast<ForwardingPlaneDetector*>(
            parent->getSubmodule("forwardingDetector"));
        fusionEngine = dynamic_cast<DSFusionEngine*>(
            parent->getSubmodule("fusionEngine"));
        strategy = dynamic_cast<AdaptiveForwardingStrategy*>(
            parent->getSubmodule("adaptiveStrategy"));
        metrics = dynamic_cast<DPIDSMetrics*>(
            parent->getSubmodule("dpidsMetrics"));

        orchestrationTimer = new cMessage("dpidsOrchestration");
        scheduleAt(simTime() + orchestrationInterval, orchestrationTimer);

        EV_INFO << "DPIDSController initialized: interval=" << orchestrationInterval
                << "s, threshold=" << beliefThreshold << endl;

        if (!featureExtractor) EV_WARN << "DPIDSController: fpFeatureExtractor not found!" << endl;
        if (!behaviouralDetector) EV_WARN << "DPIDSController: behaviouralDetector not found!" << endl;
        if (!forwardingDetector) EV_WARN << "DPIDSController: forwardingDetector not found!" << endl;
        if (!fusionEngine) EV_WARN << "DPIDSController: fusionEngine not found!" << endl;
        if (!strategy) EV_WARN << "DPIDSController: adaptiveStrategy not found!" << endl;
        if (!metrics) EV_INFO << "DPIDSController: dpidsMetrics not found (metrics disabled)" << endl;

        // Only RSU[0] creates the global dashboard to avoid duplicates
        if (getParentModule()->getIndex() == 0) {
            initCanvasDashboard();
        }
    }
}

void DPIDSController::handleMessage(cMessage *msg) {
    if (msg == orchestrationTimer) {
        orchestrate();
        scheduleAt(simTime() + orchestrationInterval, orchestrationTimer);
    } else {
        delete msg;
    }
}

void DPIDSController::collectGroundTruth() {
    // Scan all vehicles for active attack modules to build ground truth
    knownAttackers.clear();
    cModule *network = getSystemModule();

    for (cModule::SubmoduleIterator it(network); !it.end(); ++it) {
        cModule *mod = *it;
        if (std::string(mod->getName()) != "vehicle") continue;

        cModule *attackMod = mod->getSubmodule("attackModule");
        if (attackMod) {
            AttackBase *attack = dynamic_cast<AttackBase*>(attackMod);
            if (attack && attack->isAttackActive()) {
                std::string name = mod->getFullName();
                knownAttackers.insert(name);
                everAttacked.insert(name);  // Persistent record
            }
        }
    }
}

void DPIDSController::orchestrate() {
    if (!featureExtractor || !fusionEngine) return;

    // Collect ground truth for metrics
    collectGroundTruth();

    const auto &allFeatures = featureExtractor->getAllFeatures();
    int monitored = 0;
    int detected = 0;
    int penalized = 0;
    maxBeliefThisCycle = 0.0;
    detectedVehicles.clear();

    // Build vehicle module cache (non-contiguous indices with VeinsInetManager)
    std::map<std::string, cModule*> vehicleCache;
    cModule *network = getSystemModule();
    for (cModule::SubmoduleIterator it(network); !it.end(); ++it) {
        cModule *mod = *it;
        if (std::string(mod->getName()) != "vehicle") continue;
        vehicleCache[mod->getFullName()] = mod;
    }

    for (const auto &pair : allFeatures) {
        const std::string &vehicleId = pair.first;
        monitored++;

        // Check extended monitoring: force lower threshold for flagged vehicles
        double effectiveThreshold = beliefThreshold;
        if (enableExtendedMonitoring) {
            auto emIt = extendedMonitoringExpiry.find(vehicleId);
            if (emIt != extendedMonitoringExpiry.end()) {
                if (simTime() < emIt->second) {
                    effectiveThreshold = beliefThreshold * 0.5;  // Lower threshold during extended monitoring
                } else {
                    extendedMonitoringExpiry.erase(emIt);
                }
            }
        }

        // Get scores from both detectors
        double s1 = behaviouralDetector ? behaviouralDetector->getScore(vehicleId) : 0.0;
        double s2 = forwardingDetector ? forwardingDetector->getScore(vehicleId) : 0.0;

        // Fuse evidence
        auto result = fusionEngine->fuse(vehicleId, s1, s2);

        // Handle extended monitoring trigger (Section 4.4: K > K_max)
        if (result.extendedMonitoring && enableExtendedMonitoring) {
            extendedMonitoringExpiry[vehicleId] = simTime() + extendedMonitoringDuration;
            EV_INFO << "DP-IDS: Extended monitoring activated for " << vehicleId
                    << " (K=" << result.conflict << ")" << endl;
        }

        // Feed metrics with ground truth comparison
        bool actuallyMalicious = (knownAttackers.find(vehicleId) != knownAttackers.end());
        bool detectedMalicious = (result.beliefMal > effectiveThreshold);

        // Store belief for ROC curve generation
        vehicleBeliefs[vehicleId] = result.beliefMal;

        if (metrics) {
            // This records TP, TN, FP, FN for EVERY monitored vehicle EVERY cycle
            metrics->recordDetection(actuallyMalicious, detectedMalicious);
        }

        // Track max belief for visualization
        if (result.beliefMal > maxBeliefThisCycle)
            maxBeliefThisCycle = result.beliefMal;

        // Check if detected
        if (detectedMalicious) {
            detected++;
            detectedVehicles.insert(vehicleId);

            EV_WARN << "DP-IDS DETECTION: vehicle " << vehicleId
                    << " Bel(mal)=" << result.beliefMal
                    << " (s1=" << s1 << ", s2=" << s2
                    << ", K=" << result.conflict
                    << ", threshold=" << effectiveThreshold
                    << ", groundTruth=" << (actuallyMalicious ? "ATTACKER" : "BENIGN")
                    << ")" << endl;

            // Show bubble on RSU when detection occurs
            bubble("ALERT: Malicious vehicle detected!");

            // Apply penalisation using cached module reference
            if (enablePenalization && strategy) {
                auto modIt = vehicleCache.find(vehicleId);
                if (modIt != vehicleCache.end()) {
                    strategy->applyPenalization(modIt->second, vehicleId, result.beliefMal);
                    penalized++;
                }
            }
        }
    }

    // Update aggregate statistics
    currentMonitored = monitored;
    currentDetected = detected;
    totalDetections += detected;
    totalPenalizations += penalized;

    if (monitored > 0) {
        emit(vehiclesMonitoredSignal, (long)monitored);
    }
    if (detected > 0) {
        emit(vehiclesDetectedSignal, (long)detected);
    }
    if (penalized > 0) {
        emit(vehiclesPenalizedSignal, (long)penalized);
    }

    // Update vehicle display strings to show malicious/benign state
    updateVehicleVisuals();

    // Update canvas dashboard and flow lines (RSU[0] only)
    if (getParentModule()->getIndex() == 0) {
        updateCanvasDashboard();
    }
    drawPacketFlowLines();
}

void DPIDSController::initCanvasDashboard() {
    cCanvas *canvas = getSystemModule()->getCanvas();

    // Anchor the panel where the network says there is free canvas, so it does
    // not sit on top of an RSU icon. Every child figure below is offset from it.
    dashX = par("dashX").doubleValue();
    dashY = par("dashY").doubleValue();

    // --- Dark translucent panel ---
    dashPanel = new cRectangleFigure("dpidsDashPanel");
    dashPanel->setBounds(cFigure::Rectangle(dashX, dashY, 380, 280));
    dashPanel->setFilled(true);
    dashPanel->setFillColor(cFigure::Color(15, 15, 30));
    dashPanel->setFillOpacity(0.88);
    dashPanel->setLineColor(cFigure::Color(0, 200, 255));
    dashPanel->setLineWidth(2);
    dashPanel->setCornerRx(10);
    dashPanel->setCornerRy(10);
    dashPanel->setZIndex(200);
    canvas->addFigure(dashPanel);

    // --- Title ---
    dashTitle = new cTextFigure("dpidsDashTitle");
    dashTitle->setPosition(cFigure::Point(dashX + 20, dashY + 20));
    dashTitle->setFont(cFigure::Font("", 14, cFigure::FONT_BOLD));
    dashTitle->setColor(cFigure::Color(0, 255, 200));
    dashTitle->setText("DP-IDS-VNDN Dashboard");
    dashTitle->setZIndex(201);
    canvas->addFigure(dashTitle);

    // --- Threat level bar background ---
    threatBarBg = new cRectangleFigure("dpidsThreatBarBg");
    threatBarBg->setBounds(cFigure::Rectangle(dashX + 20, dashY + 45, 300, 16));
    threatBarBg->setFilled(true);
    threatBarBg->setFillColor(cFigure::Color(40, 40, 40));
    threatBarBg->setCornerRx(4);
    threatBarBg->setCornerRy(4);
    threatBarBg->setZIndex(201);
    canvas->addFigure(threatBarBg);

    // --- Threat level bar (fills proportionally) ---
    threatBar = new cRectangleFigure("dpidsThreatBar");
    threatBar->setBounds(cFigure::Rectangle(dashX + 20, dashY + 45, 0, 16));
    threatBar->setFilled(true);
    threatBar->setFillColor(cFigure::Color(0, 200, 0));
    threatBar->setCornerRx(4);
    threatBar->setCornerRy(4);
    threatBar->setZIndex(202);
    canvas->addFigure(threatBar);

    // --- Threat label ---
    threatLabel = new cTextFigure("dpidsThreatLabel");
    threatLabel->setPosition(cFigure::Point(dashX + 20, dashY + 38));
    threatLabel->setFont(cFigure::Font("", 9));
    threatLabel->setColor(cFigure::Color(180, 180, 180));
    threatLabel->setText("Threat Level: 0%");
    threatLabel->setZIndex(203);
    canvas->addFigure(threatLabel);

    // --- Stats text ---
    dashStats = new cTextFigure("dpidsDashStats");
    dashStats->setPosition(cFigure::Point(dashX + 20, dashY + 75));
    dashStats->setFont(cFigure::Font("Courier", 10));
    dashStats->setColor(cFigure::Color(200, 220, 255));
    dashStats->setText("Initializing...");
    dashStats->setZIndex(201);
    canvas->addFigure(dashStats);

    // --- DS Belief Pie Chart ---
    beliefSlice = new cPieSliceFigure("dpidsBelief");
    beliefSlice->setBounds(cFigure::Rectangle(dashX + 250, dashY + 110, 100, 100));
    beliefSlice->setFilled(true);
    beliefSlice->setFillColor(cFigure::Color(255, 60, 60));
    beliefSlice->setStartAngle(0);
    beliefSlice->setEndAngle(0);
    beliefSlice->setZIndex(201);
    canvas->addFigure(beliefSlice);

    disbeliefSlice = new cPieSliceFigure("dpidsDisbelief");
    disbeliefSlice->setBounds(cFigure::Rectangle(dashX + 250, dashY + 110, 100, 100));
    disbeliefSlice->setFilled(true);
    disbeliefSlice->setFillColor(cFigure::Color(60, 200, 60));
    disbeliefSlice->setStartAngle(0);
    disbeliefSlice->setEndAngle(360);
    disbeliefSlice->setZIndex(201);
    canvas->addFigure(disbeliefSlice);

    uncertaintySlice = new cPieSliceFigure("dpidsUncertainty");
    uncertaintySlice->setBounds(cFigure::Rectangle(dashX + 250, dashY + 110, 100, 100));
    uncertaintySlice->setFilled(true);
    uncertaintySlice->setFillColor(cFigure::Color(120, 120, 160));
    uncertaintySlice->setStartAngle(0);
    uncertaintySlice->setEndAngle(0);
    uncertaintySlice->setZIndex(201);
    canvas->addFigure(uncertaintySlice);

    pieLabel = new cTextFigure("dpidsPieLabel");
    pieLabel->setPosition(cFigure::Point(dashX + 260, dashY + 220));
    pieLabel->setFont(cFigure::Font("", 9));
    pieLabel->setColor(cFigure::Color(200, 200, 200));
    pieLabel->setText("DS Evidence");
    pieLabel->setZIndex(202);
    canvas->addFigure(pieLabel);
}

void DPIDSController::updateCanvasDashboard() {
    if (!dashPanel) return;  // Only RSU[0] has the dashboard

    // Aggregate stats across all RSUs
    int totalMon = 0, totalDet = 0, totalTP = 0, totalFP = 0;
    int numRSUs = 0;
    double avgBelief = 0;

    cModule *network = getSystemModule();
    for (int r = 0; ; r++) {
        cModule *rsu = network->getSubmodule("rsu", r);
        if (!rsu) break;
        numRSUs++;

        DPIDSController *ctrl = dynamic_cast<DPIDSController*>(
            rsu->getSubmodule("dpidsController"));
        if (!ctrl) continue;

        totalMon += ctrl->currentMonitored;
        totalDet += ctrl->currentDetected;
        avgBelief += ctrl->maxBeliefThisCycle;
    }
    if (numRSUs > 0) avgBelief /= numRSUs;

    totalTP = (int)knownAttackers.size();  // Approximate from ground truth
    totalFP = totalDetections > 0 ? std::max(0, totalDetections - totalTP * 5) : 0;

    // Update threat bar
    double threatLevel = std::min(1.0, avgBelief);
    threatBar->setBounds(cFigure::Rectangle(dashX + 20, dashY + 45, threatLevel * 300, 16));

    if (threatLevel > 0.7) {
        threatBar->setFillColor(cFigure::Color(255, 40, 40));
    } else if (threatLevel > 0.4) {
        threatBar->setFillColor(cFigure::Color(255, 165, 0));
    } else {
        threatBar->setFillColor(cFigure::Color(0, 200, 0));
    }

    char threatText[64];
    snprintf(threatText, sizeof(threatText), "Threat Level: %.0f%%", threatLevel * 100);
    threatLabel->setText(threatText);

    // Update stats text
    char stats[512];
    snprintf(stats, sizeof(stats),
             "RSUs Active:        %d\n"
             "Vehicles Monitored: %d\n"
             "Detections (cycle): %d\n"
             "Total Detections:   %d\n"
             "Known Attackers:    %d\n"
             "Avg DS Belief:      %.3f\n"
             "Threshold:          %.2f\n"
             "Sim Time:           %.1fs",
             numRSUs, totalMon, totalDet,
             totalDetections, (int)knownAttackers.size(),
             avgBelief, beliefThreshold,
             simTime().dbl());
    dashStats->setText(stats);

    // Update DS belief pie chart
    double bel = std::min(1.0, avgBelief);
    double dis = std::max(0.0, 1.0 - bel - 0.1);
    double unc = 0.1;

    beliefSlice->setStartAngle(0);
    beliefSlice->setEndAngle(bel * 360);
    disbeliefSlice->setStartAngle(bel * 360);
    disbeliefSlice->setEndAngle((bel + dis) * 360);
    uncertaintySlice->setStartAngle((bel + dis) * 360);
    uncertaintySlice->setEndAngle(360);

    char plabel[64];
    snprintf(plabel, sizeof(plabel), "Bel:%.0f%% Dis:%.0f%%", bel*100, dis*100);
    pieLabel->setText(plabel);
}

void DPIDSController::drawPacketFlowLines() {
    cCanvas *canvas = getSystemModule()->getCanvas();

    // Clear old flow lines
    for (auto *line : flowLines) {
        canvas->removeFigure(line);
        delete line;
    }
    flowLines.clear();

    for (auto *line : attackLines) {
        canvas->removeFigure(line);
        delete line;
    }
    attackLines.clear();

    cModule *network = getSystemModule();
    cModule *rsu = getParentModule();

    // Get RSU position from display string
    double rsuX = 0, rsuY = 0;
    const char *px = rsu->getDisplayString().getTagArg("p", 0);
    const char *py = rsu->getDisplayString().getTagArg("p", 1);
    if (px && *px) rsuX = atof(px);
    if (py && *py) rsuY = atof(py);

    // Draw lines from RSU to each monitored vehicle
    int lineIdx = 0;
    for (cModule::SubmoduleIterator it(network); !it.end(); ++it) {
        cModule *veh = *it;
        if (std::string(veh->getName()) != "vehicle") continue;
        lineIdx++;

        const char *vx = veh->getDisplayString().getTagArg("p", 0);
        const char *vy = veh->getDisplayString().getTagArg("p", 1);
        if (!vx || !*vx) continue;

        double vehicleX = atof(vx);
        double vehicleY = atof(vy);

        std::string vid = veh->getFullName();
        bool isDetected = (detectedVehicles.count(vid) > 0);
        bool isAttacker = (knownAttackers.count(vid) > 0);

        // Communication flow line (blue, thin)
        auto *flowLine = new cLineFigure(("flow_" + std::to_string(lineIdx)).c_str());
        flowLine->setStart(cFigure::Point(rsuX, rsuY));
        flowLine->setEnd(cFigure::Point(vehicleX, vehicleY));
        flowLine->setLineWidth(1);
        flowLine->setLineOpacity(0.25);
        flowLine->setLineColor(cFigure::Color(100, 180, 255));
        flowLine->setLineStyle(cFigure::LINE_DOTTED);
        flowLine->setZIndex(10);
        canvas->addFigure(flowLine);
        flowLines.push_back(flowLine);

        // Attack line (red, thick, with arrow) for detected attackers
        if (isDetected || isAttacker) {
            auto *atkLine = new cLineFigure(("atk_" + std::to_string(lineIdx)).c_str());
            atkLine->setStart(cFigure::Point(vehicleX, vehicleY));
            atkLine->setEnd(cFigure::Point(rsuX, rsuY));
            atkLine->setLineWidth(3);
            atkLine->setLineOpacity(0.7);
            atkLine->setEndArrowhead(cFigure::ARROW_BARBED);
            atkLine->setZIndex(50);

            if (isDetected && isAttacker) {
                // True positive - bright red
                atkLine->setLineColor(cFigure::Color(255, 0, 0));
            } else if (isDetected) {
                // False positive - orange
                atkLine->setLineColor(cFigure::Color(255, 165, 0));
                atkLine->setLineStyle(cFigure::LINE_DASHED);
            } else {
                // Undetected attacker - dark red dashed
                atkLine->setLineColor(cFigure::Color(180, 0, 0));
                atkLine->setLineStyle(cFigure::LINE_DASHED);
                atkLine->setLineOpacity(0.4);
            }

            canvas->addFigure(atkLine);
            attackLines.push_back(atkLine);
        }
    }
}

void DPIDSController::updateVehicleVisuals() {
    cModule *network = getSystemModule();
    for (cModule::SubmoduleIterator it(network); !it.end(); ++it) {
        cModule *mod = *it;
        if (std::string(mod->getName()) != "vehicle") continue;

        std::string vid = mod->getFullName();
        bool isDetected = (detectedVehicles.count(vid) > 0);
        bool isActualAttacker = (knownAttackers.count(vid) > 0);

        auto &ds = mod->getDisplayString();

        if (isDetected && isActualAttacker) {
            // True Positive: red car with exclamation
            ds.setTagArg("i", 1, "red");
            ds.setTagArg("i2", 0, "status/excl");
            ds.setTagArg("t", 0, "DETECTED");
            ds.setTagArg("t", 2, "red");
        } else if (isDetected && !isActualAttacker) {
            // False Positive: orange car
            ds.setTagArg("i", 1, "orange");
            ds.setTagArg("i2", 0, "status/yellow");
            ds.setTagArg("t", 0, "FP");
            ds.setTagArg("t", 2, "orange");
        } else if (!isDetected && isActualAttacker) {
            // False Negative: dark red (undetected attacker)
            ds.setTagArg("i", 1, "#880000");
            ds.setTagArg("i2", 0, "");
            ds.setTagArg("t", 0, "STEALTH");
            ds.setTagArg("t", 2, "#880000");
        } else {
            // True Negative: green (normal)
            ds.setTagArg("i", 1, "green");
            ds.setTagArg("i2", 0, "");
            ds.setTagArg("t", 0, "");
        }

        // Set detailed tooltip
        char tt[256];
        snprintf(tt, sizeof(tt), "%s\nAttacker: %s | Detected: %s",
                 vid.c_str(),
                 isActualAttacker ? "YES" : "no",
                 isDetected ? "YES" : "no");
        ds.setTagArg("tt", 0, tt);
    }
}

void DPIDSController::refreshDisplay() const {
    // Update RSU parent display with live IDS stats
    cModule *rsu = getParentModule();
    if (!rsu) return;

    // RSU text label: show monitoring stats
    char label[128];
    snprintf(label, sizeof(label), "Mon:%d Det:%d Tot:%d",
             currentMonitored, currentDetected, totalDetections);
    rsu->getDisplayString().setTagArg("t", 0, label);

    // Color RSU based on threat level
    if (currentDetected > 0) {
        rsu->getDisplayString().setTagArg("t", 2, "red");
        rsu->getDisplayString().setTagArg("i", 1, "red");
    } else if (maxBeliefThisCycle > 0.5) {
        rsu->getDisplayString().setTagArg("t", 2, "orange");
        rsu->getDisplayString().setTagArg("i", 1, "orange");
    } else {
        rsu->getDisplayString().setTagArg("t", 2, "#006600");
        rsu->getDisplayString().setTagArg("i", 1, "green");
    }

    // Tooltip with detailed IDS info
    char tt[512];
    snprintf(tt, sizeof(tt),
             "DP-IDS Controller\n"
             "Monitored: %d vehicles\n"
             "Detected: %d this cycle\n"
             "Total Detections: %d\n"
             "Total Penalizations: %d\n"
             "Known Attackers: %d\n"
             "Belief Threshold: %.2f\n"
             "Max Belief: %.3f",
             currentMonitored, currentDetected,
             totalDetections, totalPenalizations,
             (int)knownAttackers.size(),
             beliefThreshold, maxBeliefThisCycle);
    rsu->getDisplayString().setTagArg("tt", 0, tt);
}

void DPIDSController::finish() {
    recordScalar("totalDetections", totalDetections);
    recordScalar("totalPenalizations", totalPenalizations);
    recordScalar("knownAttackersAtEnd", (int)knownAttackers.size());
    recordScalar("everAttackedCount", (int)everAttacked.size());

    // Per-vehicle belief scores (for ROC curve generation)
    int attackerDetectedCount = 0;
    int attackerMissedCount = 0;
    double sumAttackerBelief = 0, sumBenignBelief = 0;
    int attackerBeliefCount = 0, benignBeliefCount = 0;

    for (const auto &vb : vehicleBeliefs) {
        bool isAttacker = (everAttacked.count(vb.first) > 0);
        bool wasDetected = (detectedVehicles.count(vb.first) > 0);

        if (isAttacker) {
            sumAttackerBelief += vb.second;
            attackerBeliefCount++;
            if (wasDetected) attackerDetectedCount++;
            else attackerMissedCount++;
        } else {
            sumBenignBelief += vb.second;
            benignBeliefCount++;
        }
    }

    // Detection rates
    double detectionRate = (attackerBeliefCount > 0) ?
        (double)attackerDetectedCount / attackerBeliefCount : 0.0;
    double missRate = (attackerBeliefCount > 0) ?
        (double)attackerMissedCount / attackerBeliefCount : 0.0;

    recordScalar("detectionRate", detectionRate);
    recordScalar("missRate", missRate);

    // Average beliefs (for separability analysis)
    recordScalar("avgAttackerBelief", attackerBeliefCount > 0 ?
        sumAttackerBelief / attackerBeliefCount : 0.0);
    recordScalar("avgBenignBelief", benignBeliefCount > 0 ?
        sumBenignBelief / benignBeliefCount : 0.0);
    recordScalar("attackersMonitored", attackerBeliefCount);
    recordScalar("benignMonitored", benignBeliefCount);
}

} // namespace veremivndn
