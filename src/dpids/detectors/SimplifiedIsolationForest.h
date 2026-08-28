//
// DP-IDS-VNDN - Simplified Isolation Forest (Section 4.3.2)
// Pure C++ implementation for forwarding-plane anomaly scoring
// Anomaly score proportional to inverse of average path length
//

#ifndef __VEREMIVNDN_SIMPLIFIEDISOLATIONFOREST_H
#define __VEREMIVNDN_SIMPLIFIEDISOLATIONFOREST_H

#include <vector>
#include <random>
#include <cmath>
#include <string>
#include <fstream>

namespace veremivndn {

class SimplifiedIsolationForest {
public:
    SimplifiedIsolationForest() : numTrees(0), subSampleSize(0), initialized(false) {}

    /**
     * Initialize the forest with given parameters.
     * Builds random isolation trees from normal trace data.
     * If no training data provided, uses synthetic normal distribution.
     */
    bool initialize(int numTrees, int subSampleSize, int numFeatures,
                    const std::string &modelPath = "");

    /**
     * Compute anomaly score for a feature vector.
     * Score in [0, 1] where 1 = most anomalous.
     * Based on average path length across all trees.
     */
    double score(const std::vector<double> &features);

    bool isInitialized() const { return initialized; }

private:
    struct IsolationTreeNode {
        int splitFeature;      // Feature index to split on (-1 = leaf)
        double splitValue;     // Value to split at
        int left;              // Left child index (-1 = none)
        int right;             // Right child index (-1 = none)
        int size;              // Number of samples reaching this node
    };

    struct IsolationTree {
        std::vector<IsolationTreeNode> nodes;
        int maxDepth;
    };

    int numTrees;
    int subSampleSize;
    int numFeatures;
    bool initialized;
    std::vector<IsolationTree> trees;

    // Build a single isolation tree from synthetic normal data
    IsolationTree buildTree(std::mt19937 &rng, int maxDepth);

    int buildNode(IsolationTree &tree, std::vector<std::vector<double>> &data,
                  int depth, int maxDepth, std::mt19937 &rng);

    // Compute path length for a sample in a tree
    double pathLength(const std::vector<double> &features, const IsolationTree &tree);

    // Average path length of unsuccessful search in BST
    static double averagePathLength(int n);

    // Load pre-built trees from file
    bool loadTrees(const std::string &modelPath);

    // Generate synthetic normal training data
    std::vector<std::vector<double>> generateNormalData(int n, std::mt19937 &rng);
};

} // namespace veremivndn
#endif
