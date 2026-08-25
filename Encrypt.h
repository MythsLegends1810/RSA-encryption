#pragma once
#include "Encrypt.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/integer/mod_inverse.hpp>    
using namespace boost::multiprecision;

class Variables { 
    private: 
    cpp_int P;
    cpp_int Q;
    cpp_int N; //semiprime (N = p * q))
    cpp_int T; //totient (T = (p-1)(q-1))
    cpp_int E; //
    cpp_int D;
    public: 
    Variables() {
        P = 11;
        Q = 13;
        N = P * Q;
        T = (P-1) * (Q-1);
        E = 65537;
        D = boost::integer::mod_inverse(E, T);
        
        if (miller_rabin_test(P, 25) == false) {
            std::cout << "P is not prime" << std::endl;
            exit(1);
        }
        //D = mod_inverse(E, T);

    }   
    
};