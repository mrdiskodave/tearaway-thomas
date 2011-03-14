package com.nney;

import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

class TemporaryBlockSource {
	private final int miniW;
	private final int blocksHorizontally;
	private final int blockCount;
	private final SimpleImage blocks;
	private int miniH;

	public TemporaryBlockSource(SimpleImage blocks, int miniW, int miniH) {
		this.blocks = blocks;
		this.miniW = miniW;
		this.miniH = miniH;
		int allBlocksWidth = blocks.getWidth();
		int allBlocksHeight = blocks.getHeight();
		assert allBlocksWidth % miniW == 0;
		assert allBlocksHeight % miniH == 0;
		blocksHorizontally = allBlocksWidth / miniW;
		int blocksVertically = allBlocksHeight / miniH;
		blockCount = blocksHorizontally * blocksVertically;
	}

	public TemporaryBlockSource(Openable blocksOpenable, int miniW, int miniH) {
		this(new SimpleImage(OpenableTools.load(blocksOpenable)), miniW, miniH);
	}

	SimpleImage getBlock(int b) {
		assert b < blockCount;
		int x = b % blocksHorizontally;
		int y = b / blocksHorizontally;
		x *= miniW;
		y *= miniH;
		return blocks.view(x, y, miniW, miniH);
	}

	public int getBlockCount() {
		return blockCount;
	}
}