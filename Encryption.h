#pragma once
#include <string>
#include <boost/multiprecision/cpp_int.hpp>
using namespace boost::multiprecision;

struct Encryption { 
    std::string msg{};
};

inline cpp_int convertToInt(const std::string& password) { 
    cpp_int conversion{};
    for (char c : password) { 
        conversion = conversion << 8;
        conversion += c;
    }
    return conversion;
}

inline cpp_int Encrypt(cpp_int password, cpp_int E, cpp_int N) { 
    return boost::multiprecision::powm(password, E, N);
}