# CS6204 Homework #2 Assignment
Developed by: Demetrius Davis (using Jupyter Notebook, Python 3)

Visualization and Simulation Experiments for a Random Network, Scale-Free Network, and Small World Network.

Assignment: Implement the three network models including a random network (i.e., ER network), a scale-free network (BA network), and a small world network (WS network).

*******
HW2-2a.ipynb: Visualize three network models when the total number of vertices, n, is 100 with the following design parameter values for each network (Show three figures corresponding to the three network models).

(a) Random network: G(n; p) = (100; 0:1) where p is a probability for a randomly chosen pair of vertices to be connected. Record the number of edges observed.

(b) Scale free network: G(n;m0;m0) = (100; 4; 4) where m0 is the initial number of nodes in a network and m0 is the number of edges added when a new vertex is added to the network. Note that in the beginning the network with 4 vertices will be connected among them with a complete random selection. After 4 small vertices are deployed, whenever a new vertex is added, it will follow the BA network protocol.

(c) Small world network: G(n; p;K) = (100; 0:1; 10) where p is a rewiring probability and K is the number of nearest neighbors to be connected. Note that for each vertex, a randomly chosen potential neighbor is connected with p, then remove one of previous edges connected with the vertex.

*******
HW2-2b.ipynb: Conduct the following experiments when the total number of nodes varies while other parameters are fixed as p = 0:1 for a random network, m0 = m0 = 4 for a scale-free network and p = 0.1 and K = 10 for a small world network (Show two figures where each figure should show three curves corresponding to three network models).

(a) Show a graph where x-axis is the number of nodes with 100, 500, 1000, 5000, and 10000 and y-axis is a clustering coefficient. This graph must show three curves where each curve represents each network model (i.e., a random graph, a scale-free network, and a small world network). Discuss the observed results and their implications.

(b) Conduct the same experiment as (a) but show the result with the average path length for y-axis. Discuss the observed results and their implications.
