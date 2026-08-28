//
// DP-IDS-VNDN - Simplified Isolation Forest Implementation
// Anomaly score = 2^(-E(h(x))/c(n)) where h(x) = path length, c(n) = avg BST path
//

#include "SimplifiedIsolationForest.h"
#include <algorithm>
#include <numeric>

namespace veremivndn {

bool SimplifiedIsolationForest::initialize(int nTrees, int subSample, int nFeatures,
                                            const std::string &modelPath)
{
    numTrees = nTrees;
    subSampleSize = subSample;
    numFeatures = nFeatures;

    // Try loading pre-built trees
    if (!modelPath.empty() && loadTrees(modelPath)) {
        initialized = true;
        return true;
    }

    // Build trees from synthetic normal data
    std::mt19937 rng(42);
    int maxDepth = (int)std::ceil(std::log2(subSampleSize));
    if (maxDepth < 4) maxDepth = 4;

    trees.resize(numTrees);
    for (int i = 0; i < numTrees; i++) {
        trees[i] = buildTree(rng, maxDepth);
    }

    initialized = true;
    return true;
}

double SimplifiedIsolationForest::score(const std::vector<double> &features) {
    if (!initialized || trees.empty()) return 0.5;

    // Average path length across all trees
    double totalPathLen = 0.0;
    for (const auto &tree : trees) {
        totalPathLen += pathLength(features, tree);
    }
    double avgPathLen = totalPathLen / trees.size();

    // Anomaly score = 2^(-E(h(x)) / c(n))
    double cn = averagePathLength(subSampleSize);
    if (cn <= 0) cn = 1.0;

    double anomalyScore = std::pow(2.0, -avgPathLen / cn);
    return std::max(0.0, std::min(1.0, anomalyScore));
}

SimplifiedIsolationForest::IsolationTree
SimplifiedIsolationForest::buildTree(std::mt19937 &rng, int maxDepth)
{
    IsolationTree tree;
    tree.maxDepth = maxDepth;

    // Generate synthetic normal training data (features ~ N(0.1, 0.05))
    auto data = generateNormalData(subSampleSize, rng);

    // Build tree recursively
    buildNode(tree, data, 0, maxDepth, rng);
    return tree;
}

int SimplifiedIsolationForest::buildNode(IsolationTree &tree,
                                          std::vector<std::vector<double>> &data,
                                          int depth, int maxDepth,
                                          std::mt19937 &rng)
{
    IsolationTreeNode node;
    node.size = data.size();

    // Base case: leaf node
    if (depth >= maxDepth || data.size() <= 1) {
        node.splitFeature = -1;
        node.splitValue = 0.0;
        node.left = -1;
        node.right = -1;
        int idx = tree.nodes.size();
        tree.nodes.push_back(node);
        return idx;
    }

    // Pick random feature
    std::uniform_int_distribution<int> featDist(0, numFeatures - 1);
    node.splitFeature = featDist(rng);

    // Find min/max for this feature
    double minVal = data[0][node.splitFeature];
    double maxVal = data[0][node.splitFeature];
    for (const auto &row : data) {
        double v = row[node.splitFeature];
        if (v < minVal) minVal = v;
        if (v > maxVal) maxVal = v;
    }

    if (maxVal - minVal < 1e-10) {
        // All same value - make leaf
        node.splitFeature = -1;
        node.splitValue = 0.0;
        node.left = -1;
        node.right = -1;
        int idx = tree.nodes.size();
        tree.nodes.push_back(node);
        return idx;
    }

    // Pick random split value between min and max
    std::uniform_real_distribution<double> splitDist(minVal, maxVal);
    node.splitValue = splitDist(rng);

    // Partition data
    std::vector<std::vector<double>> leftData, rightData;
    for (const auto &row : data) {
        if (row[node.splitFeature] < node.splitValue) {
            leftData.push_back(row);
        } else {
            rightData.push_back(row);
        }
    }

    // Create this node (placeholder indices)
    int nodeIdx = tree.nodes.size();
    node.left = -1;
    node.right = -1;
    tree.nodes.push_back(node);

    // Recursively build children
    if (!leftData.empty()) {
        tree.nodes[nodeIdx].left = buildNode(tree, leftData, depth + 1, maxDepth, rng);
    }
    if (!rightData.empty()) {
        tree.nodes[nodeIdx].right = buildNode(tree, rightData, depth + 1, maxDepth, rng);
    }

    return nodeIdx;
}

double SimplifiedIsolationForest::pathLength(const std::vector<double> &features,
                                              const IsolationTree &tree)
{
    if (tree.nodes.empty()) return 0.0;

    int nodeIdx = 0;
    double depth = 0.0;

    while (nodeIdx >= 0 && nodeIdx < (int)tree.nodes.size()) {
        const auto &node = tree.nodes[nodeIdx];

        // Leaf node
        if (node.splitFeature < 0 || (node.left < 0 && node.right < 0)) {
            // Add expected path length for remaining data at this leaf
            return depth + averagePathLength(node.size);
        }

        // Traverse
        int feat = node.splitFeature;
        if (feat < (int)features.size() && features[feat] < node.splitValue) {
            if (node.left >= 0) {
                nodeIdx = node.left;
            } else {
                return depth + 1.0;
            }
        } else {
            if (node.right >= 0) {
                nodeIdx = node.right;
            } else {
                return depth + 1.0;
            }
        }
        depth += 1.0;
    }

    return depth;
}

double SimplifiedIsolationForest::averagePathLength(int n) {
    if (n <= 1) return 0.0;
    if (n == 2) return 1.0;

    // c(n) = 2*H(n-1) - 2*(n-1)/n, where H(i) = ln(i) + 0.5772 (Euler-Mascheroni)
    double harmonic = std::log((double)(n - 1)) + 0.5772156649;
    return 2.0 * harmonic - 2.0 * (double)(n - 1) / (double)n;
}

std::vector<std::vector<double>> SimplifiedIsolationForest::generateNormalData(
    int n, std::mt19937 &rng)
{
    // Calibrated from Scenario A benign simulation data:
    //   Feature 1 (CS anomaly):  always 0.0 (benign never inserts into CS)
    //   Feature 2 (PIT score):   0.004-0.082 (PIT 13-273, two-phase scoring)
    //   Feature 3 (FIB/drop):    always 0.0 (no drops in benign)
    //
    // Training data must cover the FULL benign variance to prevent FP.
    // Use wider variance (3-sigma covers 99.7% of benign range)
    std::normal_distribution<double> csDist(0.0, 0.008);    // CS: always ~0
    std::normal_distribution<double> pitDist(0.04, 0.035);  // PIT: wide coverage 0-0.14
    std::normal_distribution<double> fibDist(0.0, 0.008);   // FIB: always ~0

    std::vector<std::vector<double>> data(n, std::vector<double>(numFeatures));
    for (int i = 0; i < n; i++) {
        if (numFeatures >= 1) data[i][0] = std::max(0.0, std::min(1.0, csDist(rng)));
        if (numFeatures >= 2) data[i][1] = std::max(0.0, std::min(1.0, pitDist(rng)));
        if (numFeatures >= 3) data[i][2] = std::max(0.0, std::min(1.0, fibDist(rng)));
    }
    return data;
}

bool SimplifiedIsolationForest::loadTrees(const std::string &modelPath) {
    std::ifstream file(modelPath + "/isolation_forest.dat");
    if (!file.is_open()) return false;

    int nTrees, nFeats;
    file >> nTrees >> nFeats;
    if (nTrees <= 0 || nFeats != numFeatures) return false;

    trees.resize(nTrees);
    for (int t = 0; t < nTrees; t++) {
        int nNodes, maxD;
        file >> nNodes >> maxD;
        trees[t].maxDepth = maxD;
        trees[t].nodes.resize(nNodes);
        for (int n = 0; n < nNodes; n++) {
            file >> trees[t].nodes[n].splitFeature
                 >> trees[t].nodes[n].splitValue
                 >> trees[t].nodes[n].left
                 >> trees[t].nodes[n].right
                 >> trees[t].nodes[n].size;
        }
    }

    return file.good();
}

} // namespace veremivndn
