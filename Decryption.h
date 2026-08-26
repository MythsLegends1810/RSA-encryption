#pragma once
#include <string>
#include <boost/multiprecision/cpp_int.hpp>
#include <algorithm>
using namespace boost::multiprecision;

inline cpp_int Decrypt(cpp_int code, cpp_int D, cpp_int N) {
    return boost::multiprecision::powm(code, D, N);
}

inline std::string convertToString(cpp_int code) { 
    std::string convert{};
        while (code > 0) { 
            const unsigned int byte = (code & 0xFF).convert_to<unsigned int>();
            convert += static_cast<char>(byte);
            code = code >> 8;
        }        
        reverse(convert.begin(), convert.end());
        return convert;
    }