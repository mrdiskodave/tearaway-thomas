package com.nney.datanode;

interface Builder {
	void take(Node v);

	Node value();
}
