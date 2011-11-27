package com.nney.tt.gfx;


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
		blockCount = blocksHorizontally * blocksVertically;
	}
	

	public BlockSource(SimpleImage si, int blockSize) {
		this(si, blockSize, blockSize);
	}

	public boolean isEntirely(int blockNumber, int c) {
		return getBlock(blockNumber).isEntirely(c);
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


}