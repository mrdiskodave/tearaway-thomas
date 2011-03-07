package com.nney;

import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

class TemporaryBlockSource {
	private final int blockSize;
	private final int blocksW;
	private final int blockCount;
	private final SimpleImage blocks;

	TemporaryBlockSource(Openable blocksOpenable, int blockSize) {
		this.blockSize = blockSize;
		blocks = new SimpleImage(OpenableTools.load(blocksOpenable));
		int w = blocks.getWidth();
		int h = blocks.getHeight();
		assert w % blockSize == 0;
		assert h % blockSize == 0;
		blocksW = w / blockSize;
		int blocksH = h / blockSize;
		blockCount = blocksW*blocksH;
	}
	
	SimpleImage getBlock(int b) {
		assert b < blockCount;
		int x = b % blocksW;
		int y = b / blocksW;
		x *= blockSize;
		y *= blockSize;
		return blocks.view(x, y, blockSize, blockSize); 
	}

	public int getBlockCount() {
		return blockCount;
	}
}