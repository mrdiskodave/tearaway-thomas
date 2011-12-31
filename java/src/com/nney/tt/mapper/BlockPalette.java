package com.nney.tt.mapper;

import com.nney.tt.BlockSet;
import com.nney.tt.Const;
import com.nney.utils.Math2;

/**
 * Everything about the palettes of map blocks that we display.
 */
public class BlockPalette {
	/**
	 * The colour we use to highlight the current block.
	 */
	private static final int COL_CURRENT_BLOCK = 0xffff0000;

	/**
	 * Our background colour.
	 */
	private static final int COL_BACKGROUND = 0xff0020ff;

	private final int blockCount;
	private final int bigBlockPaletteHeight;
	private final MapperGC mgc;

	private BlockSet blockSet;

	private int widthInBlocks;

	public BlockPalette(MapperGC mgc, BlockSet blockSet) {
		this.mgc = mgc;
		this.blockSet = blockSet;
		this.blockCount = blockSet.getBlockCount();
		this.bigBlockPaletteHeight = Math2.roundUpDiv(blockCount, blockSet.widthInBlocks());
		this.widthInBlocks = blockSet.widthInBlocks();
	}

	void changeBlockSet(BlockSet blockSet) {
		this.blockSet = blockSet;
		assert blockSet.getBlockCount() == blockCount;
	}

	public void showSmallPalette(int currentBlock) {
		int d = 5;
		int db = Const.BLOCK_SIZE * d;
		int sx = Math2.limit(0, widthInBlocks - d, (currentBlock % widthInBlocks) - (d / 2));
		int sy = Math2.limit(0, bigBlockPaletteHeight - d, (currentBlock / widthInBlocks - (d / 2)));
		mgc.fillRectangle(0, 0, db, db, COL_BACKGROUND);

		for (int by = 0; by < d; by++) {
			for (int bx = 0; bx < d; bx++) {
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

	public int getPaletteDelta(int dx, int dy) {
		return dy * widthInBlocks + dx;
	}
}
