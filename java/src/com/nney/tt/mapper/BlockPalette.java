package com.nney.tt.mapper;

import com.nney.tt.BlockSet;
import com.nney.tt.Const;
import com.nney.utils.Math2;

/**
 * The small-palette that pops up in the top left to show the current block.
 */
public class BlockPalette {
	private static final int SIZE_IN_BLOCKS = 5;

	private static final int SIZE_IN_PIXELS = Const.BLOCK_SIZE * SIZE_IN_BLOCKS;

	private static final int CENTRE = SIZE_IN_BLOCKS / 2;

	/**
	 * The colour we use to highlight the current block.
	 */
	private static final int COL_CURRENT_BLOCK = 0xffff0000;

	/**
	 * Our background colour.
	 */
	private static final int COL_BACKGROUND = 0xff0020a0;

	static public void showSmallPalette(MapperGC mgc, BlockSet blockSet, int currentBlock) {
		int blockCount = blockSet.getBlockCount();
		int bigBlockPaletteHeight = Math2.roundUpDiv(blockCount, blockSet.widthInBlocks());
		int widthInBlocks = blockSet.widthInBlocks();

		int sx = Math2.limit(0, widthInBlocks - SIZE_IN_BLOCKS, (currentBlock % widthInBlocks) - CENTRE);
		int sy = Math2.limit(0, bigBlockPaletteHeight - SIZE_IN_BLOCKS, (currentBlock / widthInBlocks - CENTRE));
		mgc.fillRectangle(0, 0, SIZE_IN_PIXELS + 4, SIZE_IN_PIXELS + 4, 0x80000000);
		mgc.fillRectangle(0, 0, SIZE_IN_PIXELS, SIZE_IN_PIXELS, COL_BACKGROUND);

		for (int by = 0; by < SIZE_IN_BLOCKS; by++) {
			for (int bx = 0; bx < SIZE_IN_BLOCKS; bx++) {
				int b = (sy + by) * widthInBlocks + (sx + bx);
				if (b < blockCount) {
					int x = bx * Const.BLOCK_SIZE;
					int y = by * Const.BLOCK_SIZE;
					blockSet.draw(b, x, y);
					if (currentBlock == b) {
						mgc.drawBox(x, y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, mgc.process(COL_CURRENT_BLOCK));
					}
				}
			}
		}
	}
}
