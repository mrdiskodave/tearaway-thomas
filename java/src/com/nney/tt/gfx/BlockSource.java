package com.nney.tt.gfx;

import com.nney.tt.map.BlockAliasTable;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class BlockSource {
	private final int blockWidth;
	private final int blocksHorizontally;
	private final int blockCount;
	private final SimpleImage blocks;
	private final int blockHeight;

	public BlockSource(SimpleImage blocks, int miniW, int miniH) {
		this.blocks = blocks;
		this.blockWidth = miniW;
		this.blockHeight = miniH;
		int allBlocksWidth = blocks.width();
		int allBlocksHeight = blocks.height();
		assert allBlocksWidth % miniW == 0;
		assert allBlocksHeight % miniH == 0;
		blocksHorizontally = allBlocksWidth / miniW;
		int blocksVertically = allBlocksHeight / miniH;

		int bc = blocksHorizontally * blocksVertically;
		for (;;) {
			SimpleImage blockView = getBlock(bc - 1);
			if (!blockView.isEntirely(0xffff0101)) break;
			blockView.fill(0);
			bc--;
		}
		blockCount = bc;
	}

	public BlockSource(Openable blocksOpenable, int blockSize) {
		this(new SimpleImage(OpenableTools.mustLoad(blocksOpenable)), blockSize, blockSize);
	}

	public void hideBlock(int src, int dest) {
		if (src != dest) {
//			System.out.println(String.format("Hiding %d with %d", src, dest));
			getBlock(dest).overwriteWith(getBlock(src));
		}
	}

	public Bounds getBlockBounds(int b) {
		int x = b % blocksHorizontally;
		int y = b / blocksHorizontally;
		x *= blockWidth;
		y *= blockHeight;
		return new Bounds(x, y, blockWidth, blockHeight);
	}

	public SimpleImage getBlock(int b) {
		return blocks.view(getBlockBounds(b));
	}

	public int getBlockCount() {
		return blockCount;
	}

	public int getBlockSize() {
		assert blockWidth == blockHeight;
		return blockWidth;
	}

	public void doBlockHiding(BlockAliasTable bat) {
		if (bat != null) {
			for (int b = 0; b < blockCount; b++) {
				hideBlock(bat.compress(b), b);
			}
		}
	}
}