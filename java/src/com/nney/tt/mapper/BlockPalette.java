package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.BlockSet2;
import com.nney.tt.Const;
import com.nney.tt.geom.Coord;
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
	 * The colour used to highlight the mouse-hovered block.
	 */
	private static final int COL_HOVER_BLOCK = 0xff00ff00;

	/**
	 * There is a zone in the middle that decides how much we scroll according
	 * to where the mouse is within it. We have {@link #SCROLL_MARGIN} pixels of
	 * non-zone at the top and bottom because it isn't nice if the new screen is
	 * turning up <b>just</b> as the mouse reaches the top (or bottom) of the
	 * screen.
	 */
	private static final int SCROLL_MARGIN = 64;

	/**
	 * The number of blocks we present per line. This should be the same number
	 * of blocks per line that the artist had when drawing them to that a line
	 * retains its artist-given meaning.
	 */
	private static final int BLOCKS_PER_LINE = 20;

	/**
	 * Our background colour.
	 */
	private static final int COL_BACKGROUND = 0xff0020ff;

	private final int blockCount;
	private final int bigBlockPaletteHeight;
	private final MapperGC mgc;

	private BlockSet2 blockSet;

	private class BlockPos {
		public final int x;
		public final int y;
		public final int b;

		BlockPos(int x, int y, int b) {
			this.x = x;
			this.y = y;
			this.b = b;
		}
	}

	private List<BlockPos> createBlockPosList(int sx, int sy, int width, int height, int mdx, int mdy) {
		List<BlockPos> answer = new ArrayList<BlockPos>();
		for (int by = 0; by < height; by++) {
			for (int bx = 0; bx < width; bx++) {
				int b = (sy + by) * BLOCKS_PER_LINE + (sx + bx);
				if (b < blockCount) {
					int x = bx * Const.BLOCK_SIZE + mdx;
					int y = by * Const.BLOCK_SIZE + mdy;
					answer.add(new BlockPos(x, y, b));
				}
			}
		}
		return answer;
	}

	public BlockPalette(MapperGC mgc, BlockSet2 blockSet) {
		this.mgc = mgc;
		this.blockSet = blockSet;
		this.blockCount = blockSet.getBlockCount();
		this.bigBlockPaletteHeight = Math2.roundUpDiv(blockCount, BLOCKS_PER_LINE);
	}

	public void showSmallPalette(int currentBlock) {
		int d = 5;
		int x = Math2.limit(0, BLOCKS_PER_LINE - d, (currentBlock % BLOCKS_PER_LINE) - (d / 2));
		int y = Math2.limit(0, bigBlockPaletteHeight - d, (currentBlock / BLOCKS_PER_LINE - (d / 2)));
		int db = Const.BLOCK_SIZE * d;
		int sx = 0; // mgc.screenWidth() - db;
		int sy = 0;
		mgc.fillRectangle(sx, sy, db, db, COL_BACKGROUND);
		drawIt(false, currentBlock, currentBlock, createBlockPosList(x, y, d, d, sx, sy));
	}

	private int c(int x) {
		return blockSet.compressBlock(x);
	}

	public int showBigPalette(int currentBlock, Coord mouse) {
		mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);

		int protrusion = Math.max(bigBlockPaletteHeight * Const.BLOCK_SIZE - mgc.screenHeight(), 0);
		int vscroll = computeVerticalScrollAmount(mouse.y, protrusion);
		int hoverBlock = -1;

		List<BlockPos> ps = createBlockPosList(0, 0, BLOCKS_PER_LINE, bigBlockPaletteHeight, 0, -vscroll);
		for (BlockPos p : ps) {
			if (mouse.y >= p.y && mouse.y <= p.y + 15 && mouse.x >= p.x && mouse.x <= p.x + 15) {
				hoverBlock = p.b;
			}
		}

		drawIt(true, currentBlock, hoverBlock, ps);
		return hoverBlock;
	}

	private void drawIt(boolean labels, int currentBlock, int hoverBlock, List<BlockPos> ps) {
		currentBlock = c(currentBlock);

		for (BlockPos p : ps) {
			blockSet.draw(p.b, p.x, p.y);
			if (currentBlock == c(p.b)) {
				mgc.drawBox(p.x, p.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, mgc.process(COL_CURRENT_BLOCK));
				if (labels && currentBlock == p.b) {
					mgc.drawText(BLOCKS_PER_LINE * Const.BLOCK_SIZE, p.y, COL_CURRENT_BLOCK,
							String.format("%4d", currentBlock));
				}
			}
			if (hoverBlock == p.b) {
				if (c(hoverBlock) == currentBlock) {
					mgc.drawBox(p.x + 1, p.y + 1, Const.BLOCK_SIZE - 2, Const.BLOCK_SIZE - 2,
							mgc.process(COL_HOVER_BLOCK));
				}
				else {
					mgc.drawBox(p.x, p.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, mgc.process(COL_HOVER_BLOCK));
				}
				if (labels) {
					mgc.drawText(BLOCKS_PER_LINE * Const.BLOCK_SIZE + 8 * 4, p.y, COL_HOVER_BLOCK,
							String.format("%4d", c(hoverBlock)));
				}
			}
		}
	}

	private int computeVerticalScrollAmount(int mousePos, int protrusion) {
		int scrollZoneSize = mgc.screenHeight() - 1 - SCROLL_MARGIN * 2;
		int mousePositionWithinScrollZone = Math2.limit(0, scrollZoneSize, mousePos - SCROLL_MARGIN);
		return (protrusion * mousePositionWithinScrollZone) / scrollZoneSize;
	}

	public static int getPaletteDelta(int dx, int dy) {
		return dy * BLOCKS_PER_LINE + dx;
	}
}
