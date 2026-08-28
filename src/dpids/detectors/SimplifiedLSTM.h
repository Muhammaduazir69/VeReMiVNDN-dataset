//
// DP-IDS-VNDN - Simplified LSTM Inference (Section 4.3.1)
// Pure C++ 4-layer LSTM forward pass - no LibTorch dependency
// Loads pre-trained weights from CSV or uses randomised initialization
//

#ifndef __VEREMIVNDN_SIMPLIFIEDLSTM_H
#define __VEREMIVNDN_SIMPLIFIEDLSTM_H

#include <vector>
#include <string>
#include <cmath>
#include <random>
#include <fstream>
#include <sstream>

namespace veremivndn {

class SimplifiedLSTM {
public:
    SimplifiedLSTM() : loaded(false), inputDim(0), hiddenDim(0), numLayers(0) {}

    /**
     * Initialize LSTM with given dimensions.
     * If modelPath is non-empty, loads weights from CSV files.
     * Otherwise uses Xavier initialization for realistic random scoring.
     */
    bool initialize(int inputDim, int hiddenDim, int numLayers,
                    const std::string &modelPath = "");

    /**
     * Run forward pass on a sequence of feature vectors.
     * @param sequence [seqLen][inputDim] feature vectors
     * @return Anomaly score in [0, 1] after sigmoid
     */
    double infer(const std::vector<std::vector<double>> &sequence);

    bool isLoaded() const { return loaded; }

private:
    bool loaded;
    int inputDim;
    int hiddenDim;
    int numLayers;

    // Per-layer LSTM weights: Wi, Wf, Wc, Wo (input), Ui, Uf, Uc, Uo (recurrent), biases
    struct LSTMLayerWeights {
        // Input gate: i = sigma(Wi*x + Ui*h + bi)
        std::vector<std::vector<double>> Wi;  // [hiddenDim x layerInputDim]
        std::vector<std::vector<double>> Ui;  // [hiddenDim x hiddenDim]
        std::vector<double> bi;               // [hiddenDim]

        // Forget gate: f = sigma(Wf*x + Uf*h + bf)
        std::vector<std::vector<double>> Wf;
        std::vector<std::vector<double>> Uf;
        std::vector<double> bf;

        // Cell gate: g = tanh(Wc*x + Uc*h + bc)
        std::vector<std::vector<double>> Wc;
        std::vector<std::vector<double>> Uc;
        std::vector<double> bc;

        // Output gate: o = sigma(Wo*x + Uo*h + bo)
        std::vector<std::vector<double>> Wo;
        std::vector<std::vector<double>> Uo;
        std::vector<double> bo;
    };

    std::vector<LSTMLayerWeights> layers;

    // Final FC layer: hidden -> 1 (anomaly score)
    std::vector<double> fcWeights;   // [hiddenDim]
    double fcBias;

    // Activation functions
    static double sigmoid(double x) {
        if (x > 20.0) return 1.0;
        if (x < -20.0) return 0.0;
        return 1.0 / (1.0 + std::exp(-x));
    }

    static double tanh_fn(double x) {
        return std::tanh(x);
    }

    // Matrix-vector multiply: result = W * x
    static std::vector<double> matVecMul(const std::vector<std::vector<double>> &W,
                                          const std::vector<double> &x);

    // Element-wise operations
    static std::vector<double> vecAdd(const std::vector<double> &a,
                                       const std::vector<double> &b);
    static std::vector<double> vecMul(const std::vector<double> &a,
                                       const std::vector<double> &b);

    // Single LSTM cell forward step
    void lstmCellForward(const LSTMLayerWeights &w,
                          const std::vector<double> &input,
                          std::vector<double> &hidden,
                          std::vector<double> &cell);

    // Xavier initialization
    void xavierInit(std::vector<std::vector<double>> &W, int rows, int cols,
                    std::mt19937 &rng);

    // Load weights from CSV
    bool loadWeights(const std::string &modelPath);
};

} // namespace veremivndn
#endif
