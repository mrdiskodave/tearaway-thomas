package com.nney;

import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

class TemporaryBlockSource {
	private final int blockEdgeLength;
	private final int blocksHorizontally;
	private final int blockCount;
	private final SimpleImage blocks;

	TemporaryBlockSource(Openable blocksOpenable, int blockEdgeLength) {
		this.blockEdgeLength = blockEdgeLength;
		blocks = new SimpleImage(OpenableTools.load(blocksOpenable));
		int allBlocksWidth = blocks.getWidth();
		int allBlocksHeight = blocks.getHeight();
		assert allBlocksWidth % blockEdgeLength == 0;
		assert allBlocksHeight % blockEdgeLength == 0;
		blocksHorizontally = allBlocksWidth / blockEdgeLength;
		int blocksVertically = allBlocksHeight / blockEdgeLength;
		blockCount = blocksHorizontally*blocksVertically;
	}
	
	SimpleImage getBlock(int b) {
		assert b < blockCount;
		int x = b % blocksHorizontally;
		int y = b / blocksHorizontally;
		x *= blockEdgeLength;
		y *= blockEdgeLength;
		return blocks.view(x, y, blockEdgeLength, blockEdgeLength); 
	}

	public int getBlockCount() {
		return blockCount;
	}
}