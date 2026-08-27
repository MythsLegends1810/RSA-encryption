#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include "Encryption.h"
#include "Decryption.h"
#include "rsa_keys.h"
#include <boost/multiprecision/cpp_int.hpp>
using namespace std;

using boost::multiprecision::cpp_int;

inline string getKeysFilePath() {
    ifstream check("/app/rsa_keys.txt");
    if (check.is_open()) {
        check.close();
        return "/app/rsa_keys.txt";
    }
    ofstream test("/app/rsa_keys.txt", ios::app);
    if (test.is_open()) {
        test.close();
        return "/app/rsa_keys.txt";
    }
    return "rsa_keys.txt";
}

void saveKeysToFile(const RSAKeys& keys) {
    ofstream outFile(getKeysFilePath());
    outFile << "P:" << keys.P << "\n"
            << "Q:" << keys.Q << "\n"
            << "N:" << keys.N << "\n"
            << "T:" << keys.T << "\n"
            << "E:" << keys.E << "\n"
            << "D:" << keys.D << "\n";
    outFile.close();
}

bool loadKeysFromFile(RSAKeys& keys) {
    ifstream inFile(getKeysFilePath());
    if (!inFile.is_open()) return false;

    string line;
    while (getline(inFile, line)) {
        size_t colon = line.find(':');
        if (colon == string::npos) continue;
        string key = line.substr(0, colon);
        string value = line.substr(colon + 1);
        while (!value.empty() && (value.back() == '\r' || value.back() == ' ' || value.back() == '\t' || value.back() == '\n')) {
            value.pop_back();
        }
        if (value.empty()) continue;
        if (key == "P") keys.P = cpp_int(value);
        else if (key == "Q") keys.Q = cpp_int(value);
        else if (key == "N") keys.N = cpp_int(value);
        else if (key == "T") keys.T = cpp_int(value);
        else if (key == "E") keys.E = cpp_int(value);
        else if (key == "D") keys.D = cpp_int(value);
    }
    inFile.close();
    return true;
}


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
        cerr << "Commands:" << endl;
        cerr << "  gen                           - Generate and save new key pair" << endl;
        cerr << "  encrypt <message> [E] [N]     - Encrypt message (uses saved keys or given E,N)" << endl;
        cerr << "  decrypt <encrypted> [D] [N]   - Decrypt (uses saved keys or given D,N)" << endl;
        cerr << "  sign <message> [D] [N]        - Sign message (uses saved keys or given D,N)" << endl;
        cerr << "  verify <msg> <sig> [N] [E]    - Verify (uses saved keys or given N,E)" << endl;
        return 1;
    }

    string command = argv[1];
    
    RSAKeys keys;
    bool hasSavedKeys = loadKeysFromFile(keys);

    // Skip generation check if explicit keys are provided or command is gen
    if (command != "gen" && !hasSavedKeys) {
        bool hasExplicitKeys = false;
        if (command == "encrypt" && argc >= 5) hasExplicitKeys = true;
        if (command == "decrypt" && argc >= 5) hasExplicitKeys = true;
        if (command == "sign" && argc >= 5) hasExplicitKeys = true;
        if (command == "verify" && argc >= 5) hasExplicitKeys = true;

        if (!hasExplicitKeys) {
            cerr << "Error: Keys file not found. Run 'gen' first." << endl;
            return 1;
        }
    }

    if (command == "gen") {
        keys = getRSAKeys();
        saveKeysToFile(keys);
        printKeys(keys);
    } else if (command == "encrypt" && argc >= 3) {
        string message = argv[2];
        
        // Override with provided E and N if given
        cpp_int useE = keys.E;
        cpp_int useN = keys.N;
        if (argc >= 5) {
            useE = cpp_int(argv[3]);
            useN = cpp_int(argv[4]);
        }
        
        cpp_int encoded = convertToInt(message);
        cpp_int encrypted = Encrypt(encoded, useE, useN);
        cout << "Message:" << message << endl;
        cout << "Encoded:" << encoded << endl;
        cout << "Encrypted:" << encrypted << endl;
        cout << "N:" << useN << endl;
        cout << "D:" << keys.D << endl;
    } else if (command == "decrypt" && argc >= 3) {
        string encStr = argv[2];
        cpp_int encrypted(encStr);
        
        // Override with provided D and N if given
        cpp_int useD = keys.D;
        cpp_int useN = keys.N;
        if (argc >= 5) {
            useD = cpp_int(argv[3]);
            useN = cpp_int(argv[4]);
        }
        
        cpp_int decrypted = Decrypt(encrypted, useD, useN);
        string decoded = convertToString(decrypted);
        cout << "Decrypted:" << decrypted << endl;
        cout << "Decoded:" << decoded << endl;
    } else if (command == "sign" && argc >= 3) {
        string message = argv[2];
        
        // Override with provided D and N if given
        cpp_int useD = keys.D;
        cpp_int useN = keys.N;
        if (argc >= 5) {
            useD = cpp_int(argv[3]);
            useN = cpp_int(argv[4]);
        }
        
        cpp_int encoded = convertToInt(message);
        cpp_int signature = powm(encoded, useD, useN);
        cpp_int pubE = keys.E.is_zero() ? cpp_int(65537) : keys.E;
        cout << "Message:" << message << endl;
        cout << "Encoded:" << encoded << endl;
        cout << "Signature:" << signature << endl;
        cout << "N:" << useN << endl;
        cout << "E:" << pubE << endl;
    } else if (command == "verify" && argc >= 4) {
        string message = argv[2];
        string sigStr = argv[3];
        cpp_int signature(sigStr);
        
        // Override with provided N and E if given
        cpp_int useN = keys.N;
        cpp_int useE = keys.E.is_zero() ? cpp_int(65537) : keys.E;
        
        if (argc >= 6 && string(argv[4]) != "" && string(argv[5]) != "") {
            cpp_int arg1(argv[4]);
            cpp_int arg2(argv[5]);
            if (arg1 > arg2) {
                useN = arg1;
                useE = arg2;
            } else {
                useE = arg1;
                useN = arg2;
            }
        } else if (argc >= 5 && string(argv[4]) != "") {
            cpp_int arg1(argv[4]);
            if (arg1 > 1000000) {
                useN = arg1;
            } else {
                useE = arg1;
            }
        }
        
        cpp_int decoded = powm(signature, useE, useN);
        cpp_int expected = convertToInt(message);
        cout << "Message:" << message << endl;
        cout << "Signature:" << signature << endl;
        cout << "Decoded:" << decoded << endl;
        cout << "Expected:" << expected << endl;
        cout << "Result:" << (decoded == expected ? "Valid" : "Invalid") << endl;
    } else {
        cerr << "Invalid command or arguments" << endl;
        return 1;
    }

    return 0;
}