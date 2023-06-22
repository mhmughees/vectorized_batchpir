#ifndef DATABASE_CONSTANTS_H
#define DATABASE_CONSTANTS_H

#include <limits>

namespace DatabaseConstants {

    constexpr int PolyDegree = 8192;
    constexpr int PlaintextModBitss = 22;
    constexpr int MaxAttempts = 500;
    constexpr int NumHashFunctions = 3;
    constexpr double CuckooFactor = 1.2;
    constexpr double FirstDimension = 32;
    constexpr uint64_t DefaultVal =  std::numeric_limits<uint64_t>::max();

}

#endif // DATABASE_CONSTANTS_H