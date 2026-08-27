#include <iostream>
#include <string>
#include "Encryption.h"
#include "Decryption.h"
#include "rsa_keys.h"
#include <boost/multiprecision/cpp_int.hpp>
using namespace std;

using boost::multiprecision::cpp_int;

void printKeys(const RSAKeys& keys) {
    cout << "P:" << keys.P << endl;
    cout << "Q:" << keys.Q << endl;
    cout << "N:" << keys.N << endl;
    cout << "T:" << keys.T << endl;
    cout << "E:" << keys.E << endl;
    cout << "D:" << keys.D << endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: backend <command> [args]" << endl;
        cerr << "Commands: gen, encrypt, decrypt, sign, verify" << endl;
        return 1;
    }

    string command = argv[1];
    RSAKeys keys = getRSAKeys();

    if (command == "gen") {
        printKeys(keys);
    } else if (command == "encrypt" && argc >= 3) {
        string message = argv[2];
        cpp_int encoded = convertToInt(message);
        cpp_int encrypted = Encrypt(encoded, keys.E, keys.N);
        cout << "Message: " << message << endl;
        cout << "Encoded: " << encoded << endl;
        cout << "Encrypted: " << encrypted << endl;
        cout << "P: " << keys.P << endl;
        cout << "Q: " << keys.Q << endl;
        cout << "N: " << keys.N << endl;
        cout << "E: " << keys.E << endl;
        cout << "D: " << keys.D << endl;
    } else if (command == "decrypt" && argc >= 4) {
        string encStr = argv[2];
        string pStr = argv[3];
        string qStr = argv[4];
        cpp_int encrypted(encStr);
        cpp_int P(pStr), Q(qStr);
        cpp_int N = P * Q;
        cpp_int T = (P - 1) * (Q - 1);
        cpp_int E = 65537;
        cpp_int D = modInverse(E, T);
        cpp_int decrypted = Decrypt(encrypted, D, N);
        string decoded = convertToString(decrypted);
        cout << "Decrypted: " << decrypted << endl;
        cout << "Decoded: " << decoded << endl;
    } else if (command == "sign" && argc >= 3) {
        string message = argv[2];
        cpp_int encoded = convertToInt(message);
        // Sign with private key D
        cpp_int signature = powm(encoded, keys.D, keys.N);
        cout << "Message: " << message << endl;
        cout << "Encoded: " << encoded << endl;
        cout << "Signature: " << signature << endl;
        cout << "N: " << keys.N << endl;
        cout << "D: " << keys.D << endl;
    } else if (command == "verify" && argc >= 5) {
        string message = argv[2];
        string sigStr = argv[3];
        string nStr = argv[4];
        cpp_int signature(sigStr);
        cpp_int N(nStr);
        // Verify with public key E
        cpp_int decoded = powm(signature, keys.E, N);
        cpp_int expected = convertToInt(message);
        cout << "Message: " << message << endl;
        cout << "Signature: " << signature << endl;
        cout << "Decoded from signature: " << decoded << endl;
        cout << "Expected: " << expected << endl;
        cout << "Result: " << (decoded == expected ? "Valid" : "Invalid") << endl;
    } else {
        cerr << "Invalid command or arguments" << endl;
        return 1;
    }

    return 0;
}