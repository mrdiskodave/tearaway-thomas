package com.nney;

import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

class TemporaryBlockSource {
	private final int miniW;
	private final int blocksHorizontally;
	private final int blockCount;
	private final SimpleImage blocks;

	public TemporaryBlockSource(Openable blocksOpenable, int miniW, int miniH) {
		this.miniW = miniW;
		blocks = new SimpleImage(OpenableTools.load(blocksOpenable));
		int allBlocksWidth = blocks.getWidth();
		int allBlocksHeight = blocks.getHeight();
		assert allBlocksWidth % miniW == 0;
		assert allBlocksHeight % miniH == 0;
		blocksHorizontally = allBlocksWidth / miniW;
		int blocksVertically = allBlocksHeight / miniH;
		blockCount = blocksHorizontally*blocksVertically;
	}
	
	SimpleImage getBlock(int b) {
		assert b < blockCount;
		int x = b % blocksHorizontally;
		int y = b / blocksHorizontally;
		x *= miniW;
		y *= miniW;
		return blocks.view(x, y, miniW, miniW); 
	}

	public int getBlockCount() {
		return blockCount;
	}
}