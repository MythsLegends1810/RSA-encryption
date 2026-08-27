#ifndef RSA_KEYS_H
#define RSA_KEYS_H

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/fwd.hpp>

#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/random.hpp>
#include <ctime>

using boost::multiprecision::cpp_int;

struct RSAKeys {
	cpp_int P;
	cpp_int Q;
	cpp_int N;
	cpp_int T;
	cpp_int E;
	cpp_int D;
};

inline cpp_int gcd(cpp_int a, cpp_int b) { // gcd function added;-KD
	
	while (b != 0) {
		cpp_int remainder = a % b;
		a = b;
		b = remainder;
	}
	return a;
}

inline cpp_int modInverse(cpp_int a, cpp_int m) { // modInverse function added;-KD
	
	cpp_int t = 0;
	cpp_int newT = 1;

	cpp_int r = m;
	cpp_int newR = a;

	while (newR != 0) {
		cpp_int quotient = r / newR;

		cpp_int temp = t;
		t = newT;
		newT = temp - quotient * newT;

		temp = r;
		r = newR;
		newR = temp - quotient * newR;
	}
	t = t % m;

	if (t < 0) {
		t = t + m;
	}

	return t;
}

inline cpp_int generatePrime() { // Created generatePrime function;-KD
	
	static boost::random::mt19937 candidateGenerator(
		static_cast<unsigned>(std::time(nullptr))
	);

	static boost::random::mt19937 testGenerator(
		static_cast<unsigned>(std::time(nullptr)) + 1
	);

	while (true) {
		cpp_int candidate = 0;

		for (int i = 0; i < 8; i++) {
			candidate <<= 32;
			candidate += candidateGenerator();
		}

		candidate |= (cpp_int(1) << 255);
		candidate |= 1;

		if (boost::multiprecision::miller_rabin_test(
			candidate, 25, testGenerator))
		{
		return candidate;
		}
	}
}

inline RSAKeys getRSAKeys() {
	RSAKeys keys;

	// These are my temporary RSA values for testing below;-KD
	// keys.P = 307;
	// keys.Q = 311;

	// keys.N = keys.P * keys.Q;
	// keys.T = (keys.P - 1) * (keys.Q -1);

	// keys.E = 65537;
	// keys.D = 54953;

	keys.E = 65537;

	do {
		keys.P = generatePrime();

		do {
			keys.Q = generatePrime();
		}
		while (keys.Q == keys.P);

		keys.N = keys.P * keys.Q;
		keys.T = (keys.P - 1) * (keys.Q - 1);
	}
	while (gcd(keys.E,keys.T) != 1);

	keys.D = modInverse(keys.E,keys.T);

	return keys;
}

#endif
