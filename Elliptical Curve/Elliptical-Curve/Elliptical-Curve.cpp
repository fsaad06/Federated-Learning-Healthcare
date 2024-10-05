#include <iostream>
#include <cryptlib.h>
#include <osrng.h>
#include <eccrypto.h>
#include <oids.h>
#include <integer.h>
#include <ecp.h>
#include <hex.h>
#include <vector>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cmath>
#include <random>

using namespace CryptoPP;
using namespace std;

// Function to compute the scalar from the elliptic curve point using brute-force
Integer ComputeScalarFromPoint(const ECP::Point& point, const DL_GroupParameters_EC<ECP>& curve, const ECP::Point& basePoint) {
    Integer order = curve.GetSubgroupOrder();
    ECP::Point currentPoint;
    Integer scalar;

    // Brute-force search (not suitable for large fields)
    for (scalar = Integer::Zero(); scalar < order; ++scalar) {
        currentPoint = curve.GetCurve().ScalarMultiply(basePoint, scalar);
        if (currentPoint == point) {
            return scalar;
        }
    }

    throw std::runtime_error("Scalar not found; discrete logarithm computation failed.");
}

// Custom function to print an ECP::Point
void PrintPoint(const ECP::Point& point) {
    cout << endl << "\t >> x: 0x" << std::hex << point.x << endl
        << "\t >> y: 0x" << std::hex << point.y << endl;
}

// Function to add Laplace noise for differential privacy
double AddLaplaceNoise(double sensitivity, double epsilon) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::exponential_distribution<> d(epsilon / sensitivity);

    double u = std::generate_canonical<double, 10>(gen) - 0.5;
    return (u < 0) ? -d(gen) : d(gen);
}

int main() {
    AutoSeededRandomPool rng;

    // Choose a curve, for example, secp256k1
    OID curveOID = ASN1::secp256k1();
    DL_GroupParameters_EC<ECP> curve;
    curve.Initialize(curveOID);

    ECP::Point g1 = curve.GetSubgroupGenerator();
    ECP::Point g2 = curve.GetSubgroupGenerator();
    Integer order = curve.GetSubgroupOrder();

    size_t numParticipants = 10;
    vector<Integer> secretValues(numParticipants);
    vector<Integer> randomValues(numParticipants);
    vector<ECP::Point> R(numParticipants);
    vector<ECP::Point> C(numParticipants);

    // Generate random values and calculate public parameters
    Integer sumRandomValues = Integer::Zero();
    for (size_t i = 0; i < numParticipants - 1; ++i) {
        secretValues[i] = Integer(99);
        randomValues[i] = Integer(rng, Integer::One(), order - 1);

        R[i] = curve.GetCurve().ScalarMultiply(g1, randomValues[i]);
        C[i] = curve.GetCurve().Add(curve.GetCurve().ScalarMultiply(g2, randomValues[i]), curve.GetCurve().ScalarMultiply(g2, secretValues[i]));
    }

    // Aggregation and verification
    ECP::Point aggregatedR = curve.GetCurve().Identity();
    ECP::Point aggregatedC = curve.GetCurve().Identity();

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < numParticipants; ++i) {
        aggregatedR = curve.GetCurve().Add(aggregatedR, R[i]);
        aggregatedC = curve.GetCurve().Add(aggregatedC, C[i]);
    }

    ECP::Point secretFinal = curve.GetCurve().Subtract(aggregatedC, aggregatedR);
    try {
        Integer secretScalar = ComputeScalarFromPoint(secretFinal, curve, g2);

        // Adding Laplace noise for differential privacy
        double sensitivity = 1.0; // Sensitivity depends on the query function
        double epsilon = 0.1; // Privacy parameter

        double noisyResult = static_cast<double>(secretScalar.ConvertToLong()) + AddLaplaceNoise(sensitivity, epsilon);

        cout << endl << std::dec << "===>> Recovered Final Secret Value with Noise: " << noisyResult << endl;
    }
    catch (const std::exception& e) {
        cerr << e.what() << endl;
    }

    auto end = std::chrono::high_resolution_clock::now();

    // Calculate the duration
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    // Print the inference time
    std::cout << "Inference time: " << duration << " microseconds" << std::endl;

    return 0;
}
