# Vectorized Batch Private Information Retrieval

This repository contains an implementation of the Vectorized Batch Private Information Retrieval (PIR) Protocol published in IEEE Security and Privacy, 2023. The protocol introduces a novel approach where both communication and computation are amortized over a batch of entries, resulting in significantly lower communication overhead for small entry sizes (ranging from 32 bytes to 256 bytes). Specifically, for a batch of 256 entries and an entry size of 32 bytes, the communication overhead is 11 times less compared to previous schemes.

The paper detailing the protocol can be found [here](https://ia.cr/2022/1262).

## Dependencies

This code relies on the [Microsoft SEAL Library](https://github.com/Microsoft/SEAL#citing-microsoft-seal). Make sure to install version 4.1 of this library globally.

## Compilation

Before proceeding with the compilation, ensure that your system has [CMake](https://cmake.org) installed, preferably a version above 3.0.

After installing CMake and the Microsoft SEAL Library, navigate to the root directory of the project and execute the following commands:

```
cmake -S . -B build
cmake --build build
```

Once the build process is complete, run the following command to execute the Vectorized Batch PIR:

```
./build/bin/vectorized_batch_pir
```

This will run the Vectorized Batch PIR for the three input scenarios mentioned below:

| Batch Size | Database Size | Entry Size |
|------------|---------------|------------|
| 32         | 1048576       | 32         |
| 64         | 10485         | 256        |
| 256        | 10485         | 256        |

## Expected Output

Upon processing the inputs, the terminal should display a similar output:

![Terminal Output](https://github.com/mhmughees/vectorized_batchpir/assets/6435443/5112f7e3-2087-4223-88f1-4abf2037357d)


## FHE Parameter Selection

The performance of the protocol heavily relies on the selection of fully homomorphic encryption (FHE) parameters. We have provided the best-performing parameters for the given example inputs. However, we encourage developers to select the parameters that yield the best performance for their specific applications. Please refer to [this section](https://github.com/mhmughees/vectorized_batchpir/blob/370780f0bd58a99f18dda60e6fb2cde5c2e815f4/src/utils.h#L108) for parameter selection details.

## Contributors
 - [Muhammad Haris Mughees(Lead)](https://mhmughees.github.io)
 - [Ling Ren](https://sites.google.com/view/renling)

*Acknowledgment: Sun I (is16@illinois.edu) for helping with testing the code*

## ⚠️ Important Warning

This implementation is intended for research purposes only. The code has NOT been vetted by security experts. Therefore, no part of this code should be used in any real-world or production setting.
