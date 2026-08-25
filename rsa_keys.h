#ifndef RSA_KEYS_H
#define RSA_KEYS_H

#include <boost/multiprecision/cpp_int.h>

using boost::multiprecision::cpp_int;

struct RSAKeys {
	cpp_int P;
	cpp_int Q;
	cpp_int N;
	cpp_int T;
	cpp_int E;
	cpp_int D;
};

inline RSAKeys getRSAKeys() {
	RSAKeys keys;

	// These are my temporary RSA values for testing below;-KD
	keys.P = 307;
	keys.Q = 311;

	keys.N = keys.P * keys.Q;
	keys.T = (keys.P - 1) * (keys.Q -1);

	keys.E = 65537;
	keys.D = 54953;

	return keys;
}

#endif
