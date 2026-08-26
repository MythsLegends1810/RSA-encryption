#include <iostream>
#include "Encryption.h"
#include "Decryption.h"
#include "rsa_keys.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <string>
using namespace std;

int main() {
	const RSAKeys keys = getRSAKeys();
    cout << "Please enter a message to encrypt: " << endl;
    string message{};
    getline(cin, message);
    
	const cpp_int encoded = convertToInt(message);
	const cpp_int encrypted = Encrypt(encoded, keys.E, keys.N);
	const cpp_int decrypted = Decrypt(encrypted, keys.D, keys.N);
	const std::string decoded = convertToString(decrypted);

    cout << "Message: " << message << endl;
    cout << "Encoded: " << encoded << endl;
    cout << "Encrypted: " << encrypted << endl;
    cout << "Decrypted: " << decrypted << endl;
    cout << "Decoded: " << decoded << endl;
    cout << "Result: " << endl;
    if (decoded == message) { 
        cout << "Pass" << endl;
    }
    else {
        cout << "Fail" << endl;
    } 
	return decoded == message ? 0 : 1;
}

