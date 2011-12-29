package com.nney.tt;

public interface Const {
	int BLOCK_SHIFT = 4;
	int BLOCK_SIZE = 1 << BLOCK_SHIFT;
	int BLOCK_MASK = BLOCK_SIZE - 1;

	int FPS = 50;
}
