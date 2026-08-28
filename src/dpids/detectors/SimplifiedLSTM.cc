//
// DP-IDS-VNDN - Simplified LSTM Implementation
// Pure C++ 4-layer LSTM forward pass for behavioural anomaly scoring
//

#include "SimplifiedLSTM.h"
#include <iostream>
#include <algorithm>

namespace veremivndn {

bool SimplifiedLSTM::initialize(int inDim, int hDim, int nLayers,
                                 const std::string &modelPath)
{
    inputDim = inDim;
    hiddenDim = hDim;
    numLayers = nLayers;

    // Try loading pre-trained weights
    if (!modelPath.empty() && loadWeights(modelPath)) {
        loaded = true;
        return true;
    }

    // Xavier random initialization for simulation use
    std::mt19937 rng(42);  // Fixed seed for reproducibility
    layers.resize(numLayers);

    for (int l = 0; l < numLayers; l++) {
        int layerInput = (l == 0) ? inputDim : hiddenDim;
        auto &lw = layers[l];

        xavierInit(lw.Wi, hiddenDim, layerInput, rng);
        xavierInit(lw.Ui, hiddenDim, hiddenDim, rng);
        lw.bi.assign(hiddenDim, 0.0);

        xavierInit(lw.Wf, hiddenDim, layerInput, rng);
        xavierInit(lw.Uf, hiddenDim, hiddenDim, rng);
        lw.bf.assign(hiddenDim, 1.0);  // Forget gate bias = 1 (standard practice)

        xavierInit(lw.Wc, hiddenDim, layerInput, rng);
        xavierInit(lw.Uc, hiddenDim, hiddenDim, rng);
        lw.bc.assign(hiddenDim, 0.0);

        xavierInit(lw.Wo, hiddenDim, layerInput, rng);
        xavierInit(lw.Uo, hiddenDim, hiddenDim, rng);
        lw.bo.assign(hiddenDim, 0.0);
    }

    // FC layer: hidden -> 1
    std::uniform_real_distribution<double> fcDist(-0.1, 0.1);
    fcWeights.resize(hiddenDim);
    for (int i = 0; i < hiddenDim; i++) {
        fcWeights[i] = fcDist(rng);
    }
    fcBias = 0.0;

    loaded = true;
    return true;
}

double SimplifiedLSTM::infer(const std::vector<std::vector<double>> &sequence) {
    if (!loaded || sequence.empty()) return 0.5;

    int seqLen = sequence.size();

    // Initialize hidden and cell states for each layer
    std::vector<std::vector<double>> hiddens(numLayers, std::vector<double>(hiddenDim, 0.0));
    std::vector<std::vector<double>> cells(numLayers, std::vector<double>(hiddenDim, 0.0));

    // Process each timestep
    for (int t = 0; t < seqLen; t++) {
        std::vector<double> layerInput = sequence[t];

        // Pass through each LSTM layer
        for (int l = 0; l < numLayers; l++) {
            lstmCellForward(layers[l], layerInput, hiddens[l], cells[l]);
            layerInput = hiddens[l];  // Output of this layer = input to next
        }
    }

    // FC layer on final hidden state of last layer
    const auto &finalHidden = hiddens[numLayers - 1];
    double logit = fcBias;
    for (int i = 0; i < hiddenDim; i++) {
        logit += fcWeights[i] * finalHidden[i];
    }

    return sigmoid(logit);
}

void SimplifiedLSTM::lstmCellForward(const LSTMLayerWeights &w,
                                      const std::vector<double> &input,
                                      std::vector<double> &hidden,
                                      std::vector<double> &cell)
{
    // Input gate: i = sigma(Wi*x + Ui*h + bi)
    auto ig = vecAdd(vecAdd(matVecMul(w.Wi, input), matVecMul(w.Ui, hidden)), w.bi);
    for (auto &v : ig) v = sigmoid(v);

    // Forget gate: f = sigma(Wf*x + Uf*h + bf)
    auto fg = vecAdd(vecAdd(matVecMul(w.Wf, input), matVecMul(w.Uf, hidden)), w.bf);
    for (auto &v : fg) v = sigmoid(v);

    // Cell gate: g = tanh(Wc*x + Uc*h + bc)
    auto cg = vecAdd(vecAdd(matVecMul(w.Wc, input), matVecMul(w.Uc, hidden)), w.bc);
    for (auto &v : cg) v = tanh_fn(v);

    // Output gate: o = sigma(Wo*x + Uo*h + bo)
    auto og = vecAdd(vecAdd(matVecMul(w.Wo, input), matVecMul(w.Uo, hidden)), w.bo);
    for (auto &v : og) v = sigmoid(v);

    // Update cell: c = f * c_prev + i * g
    cell = vecAdd(vecMul(fg, cell), vecMul(ig, cg));

    // Update hidden: h = o * tanh(c)
    std::vector<double> tanhC(cell.size());
    for (size_t i = 0; i < cell.size(); i++) tanhC[i] = tanh_fn(cell[i]);
    hidden = vecMul(og, tanhC);
}

std::vector<double> SimplifiedLSTM::matVecMul(
    const std::vector<std::vector<double>> &W,
    const std::vector<double> &x)
{
    std::vector<double> result(W.size(), 0.0);
    for (size_t i = 0; i < W.size(); i++) {
        double sum = 0.0;
        size_t cols = std::min(W[i].size(), x.size());
        for (size_t j = 0; j < cols; j++) {
            sum += W[i][j] * x[j];
        }
        result[i] = sum;
    }
    return result;
}

std::vector<double> SimplifiedLSTM::vecAdd(const std::vector<double> &a,
                                            const std::vector<double> &b)
{
    size_t n = std::min(a.size(), b.size());
    std::vector<double> result(n);
    for (size_t i = 0; i < n; i++) result[i] = a[i] + b[i];
    return result;
}

std::vector<double> SimplifiedLSTM::vecMul(const std::vector<double> &a,
                                            const std::vector<double> &b)
{
    size_t n = std::min(a.size(), b.size());
    std::vector<double> result(n);
    for (size_t i = 0; i < n; i++) result[i] = a[i] * b[i];
    return result;
}

void SimplifiedLSTM::xavierInit(std::vector<std::vector<double>> &W,
                                 int rows, int cols, std::mt19937 &rng)
{
    double limit = std::sqrt(6.0 / (rows + cols));
    std::uniform_real_distribution<double> dist(-limit, limit);
    W.resize(rows, std::vector<double>(cols));
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            W[i][j] = dist(rng);
        }
    }
}

bool SimplifiedLSTM::loadWeights(const std::string &modelPath) {
    // Attempt to load weights from CSV files in modelPath directory
    // Expected files: layer{L}_{Wi,Wf,Wc,Wo,Ui,Uf,Uc,Uo,bi,bf,bc,bo}.csv
    // fc_weights.csv, fc_bias.csv

    layers.resize(numLayers);

    for (int l = 0; l < numLayers; l++) {
        int layerInput = (l == 0) ? inputDim : hiddenDim;
        std::string prefix = modelPath + "/layer" + std::to_string(l) + "_";

        auto loadMatrix = [&](const std::string &filename,
                               std::vector<std::vector<double>> &mat,
                               int rows, int cols) -> bool {
            std::ifstream file(filename);
            if (!file.is_open()) return false;
            mat.resize(rows, std::vector<double>(cols));
            for (int i = 0; i < rows; i++) {
                std::string line;
                if (!std::getline(file, line)) return false;
                std::istringstream iss(line);
                for (int j = 0; j < cols; j++) {
                    char comma;
                    if (!(iss >> mat[i][j])) return false;
                    if (j < cols - 1) iss >> comma;
                }
            }
            return true;
        };

        auto loadVector = [&](const std::string &filename,
                               std::vector<double> &vec, int size) -> bool {
            std::ifstream file(filename);
            if (!file.is_open()) return false;
            vec.resize(size);
            for (int i = 0; i < size; i++) {
                if (!(file >> vec[i])) return false;
            }
            return true;
        };

        auto &lw = layers[l];
        if (!loadMatrix(prefix + "Wi.csv", lw.Wi, hiddenDim, layerInput)) return false;
        if (!loadMatrix(prefix + "Wf.csv", lw.Wf, hiddenDim, layerInput)) return false;
        if (!loadMatrix(prefix + "Wc.csv", lw.Wc, hiddenDim, layerInput)) return false;
        if (!loadMatrix(prefix + "Wo.csv", lw.Wo, hiddenDim, layerInput)) return false;
        if (!loadMatrix(prefix + "Ui.csv", lw.Ui, hiddenDim, hiddenDim)) return false;
        if (!loadMatrix(prefix + "Uf.csv", lw.Uf, hiddenDim, hiddenDim)) return false;
        if (!loadMatrix(prefix + "Uc.csv", lw.Uc, hiddenDim, hiddenDim)) return false;
        if (!loadMatrix(prefix + "Uo.csv", lw.Uo, hiddenDim, hiddenDim)) return false;
        if (!loadVector(prefix + "bi.csv", lw.bi, hiddenDim)) return false;
        if (!loadVector(prefix + "bf.csv", lw.bf, hiddenDim)) return false;
        if (!loadVector(prefix + "bc.csv", lw.bc, hiddenDim)) return false;
        if (!loadVector(prefix + "bo.csv", lw.bo, hiddenDim)) return false;
    }

    // FC layer
    std::ifstream fcFile(modelPath + "/fc_weights.csv");
    if (!fcFile.is_open()) return false;
    fcWeights.resize(hiddenDim);
    for (int i = 0; i < hiddenDim; i++) {
        if (!(fcFile >> fcWeights[i])) return false;
    }

    std::ifstream biasFile(modelPath + "/fc_bias.csv");
    if (biasFile.is_open()) {
        biasFile >> fcBias;
    } else {
        fcBias = 0.0;
    }

    return true;
}

} // namespace veremivndn
