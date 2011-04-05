package com.nney;

import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class TemporaryBlockSource {
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
		
		int bc = blocksHorizontally * blocksVertically;
		for (;;) {
			SimpleImage blockView = getBlock(bc-1); 
			if (!blockView.isEntirely(0xffff0101)) break;
			blockView.fill(0);
			bc--;
		}
		blockCount = bc;
	}

	public TemporaryBlockSource(Openable blocksOpenable, int miniW, int miniH) {
		this(new SimpleImage(OpenableTools.mustLoad(blocksOpenable)), miniW, miniH);
	}

	Bounds getBlockBounds(int b) {
		int x = b % blocksHorizontally;
		int y = b / blocksHorizontally;
		x *= miniW;
		y *= miniH;
		return new Bounds(x, y, miniW, miniH);
	}

	public SimpleImage getBlock(int b) {
		return blocks.view(getBlockBounds(b));
	}

	public int getBlockCount() {
		return blockCount;
	}
}