#include "Bridges.h"
#include "GraphAdjList.h"
#include "rsa_keys.h"

#include <cstdlib>
// #include "/public/read.h" // Mr. Kerney's own library. Replaces iostream;-KD
#include <iostream>
#include <string>

using namespace std;
using namespace bridges;
using namespace bridges::datastructure;

int main() {

	const char* bridgesUser = getenv("BRIDGES_USER");
	const char* bridgesKey = getenv("BRIDGES_API_KEY");

	if (bridgesUser == nullptr || bridgesKey == nullptr) {
		cerr << "BRIDGES username or API key is not set." << endl;
		return 1;
	}

	RSAKeys keys = getRSAKeys();

	Bridges bridges(1, bridgesUser, bridgesKey);

	bridges.setTitle("RSA Key Generation");
	bridges.setDescription(
		"Visualization of the relationships between P, Q, N, T, E, and D in RSA."
	);

	GraphAdjList<string, string> graph;

	graph.addVertex("P");
    graph.addVertex("Q");
    graph.addVertex("N");
    graph.addVertex("T");
    graph.addVertex("E");
    graph.addVertex("D");
    graph.addVertex("PublicKey");
    graph.addVertex("PrivateKey");

    graph.getVertex("P")->setLabel("P: generated prime");
    graph.getVertex("Q")->setLabel("Q: generated prime");

    graph.getVertex("N")->setLabel("N = P * Q");
    graph.getVertex("T")->setLabel("T = (P - 1)(Q - 1)");

    graph.getVertex("E")->setLabel("E = 65537");
    graph.getVertex("D")->setLabel("D = E^-1 mod T");

    graph.getVertex("PublicKey")->setLabel("Public Key = (E, N)");
    graph.getVertex("PrivateKey")->setLabel("Private Key = (D, N)");

    graph.addEdge("P", "N");
    graph.addEdge("Q", "N");

    graph.addEdge("P", "T");
    graph.addEdge("Q", "T");

    graph.addEdge("T", "D");
    graph.addEdge("E", "D");

    graph.addEdge("E", "PublicKey");
    graph.addEdge("N", "PublicKey");

    graph.addEdge("D", "PrivateKey");
    graph.addEdge("N", "PrivateKey");
	
	bridges.setDataStructure(&graph);
	bridges.visualize();

	return 0;
}
