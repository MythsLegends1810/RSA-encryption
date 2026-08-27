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

const string KEYS_FILE = "/app/rsa_keys.json";

void saveKeysToFile(const RSAKeys& keys) {
    ofstream outFile(KEYS_FILE);
    outFile << "{\"P\":\"" << keys.P << "\",\"Q\":\"" << keys.Q 
            << "\",\"N\":\"" << keys.N << "\",\"T\":\"" << keys.T 
            << "\",\"E\":\"" << keys.E << "\",\"D\":\"" << keys.D << "\"}";
    outFile.close();
}
bool loadKeysFromFile(RSAKeys& keys) {
    ifstream inFile(KEYS_FILE);
    if (!inFile.is_open()) return false;
    
    stringstream buffer;
    buffer << inFile.rdbuf();
    string json = buffer.str();
    inFile.close();
    
    auto extractString = [&](const string& key) -> string {
        size_t start = json.find("\"" + key + "\":\"");
        if (start == string::npos) return "";
        start += key.length() + 5;
        size_t end = json.find("\"", start);
        return json.substr(start, end - start);
    };
    
    keys.P = cpp_int(extractString("P"));
    keys.Q = cpp_int(extractString("Q"));
    keys.N = cpp_int(extractString("N"));
    keys.T = cpp_int(extractString("T"));
    keys.E = cpp_int(extractString("E"));
    keys.D = cpp_int(extractString("D"));
    
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

    // Skip generation for gen command even if no saved keys exist yet
    if (command != "gen" && !hasSavedKeys) {
        cerr << "Error: Keys file not found. Run 'gen' first." << endl;
        return 1;
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
        cout << "E:" << useE << endl;
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
        cout << "Message:" << message << endl;
        cout << "Encoded:" << encoded << endl;
        cout << "Signature:" << signature << endl;
        cout << "N:" << useN << endl;
        cout << "D:" << useD << endl;
    } else if (command == "verify" && argc >= 4) {
        string message = argv[2];
        string sigStr = argv[3];
        cpp_int signature(sigStr);
        
        // Override with provided N and E if given
        cpp_int useN = keys.N;
        cpp_int useE = keys.E;
        if (argc >= 6) {
            useN = cpp_int(argv[4]);
            useE = cpp_int(argv[5]);
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