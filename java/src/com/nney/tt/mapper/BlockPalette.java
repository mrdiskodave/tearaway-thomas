package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.BlockSet;
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
	private static final int SCROLL_MARGIN2 = 64;

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

	private BlockSet blockSet;

	private ScrollingWithMargin swm;

	private int hoverBlock;

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

	public BlockPalette(MapperGC mgc, BlockSet blockSet) {
		this.mgc = mgc;
		this.blockSet = blockSet;
		this.blockCount = blockSet.getBlockCount();
		this.bigBlockPaletteHeight = Math2.roundUpDiv(blockCount, BLOCKS_PER_LINE);
		int screen = mgc.screenHeight();
		int canvas = bigBlockPaletteHeight * Const.BLOCK_SIZE;
		this.swm = new ScrollingWithMargin(screen, canvas, SCROLL_MARGIN2);
	}

	void changeBlockSet(BlockSet blockSet) {
		this.blockSet = blockSet;
		assert blockSet.getBlockCount() == blockCount;
	}

	public void showSmallPalette(int currentBlock) {
		int d = 5;
		int x = Math2.limit(0, BLOCKS_PER_LINE - d, (currentBlock % BLOCKS_PER_LINE) - (d / 2));
		int y = Math2.limit(0, bigBlockPaletteHeight - d, (currentBlock / BLOCKS_PER_LINE - (d / 2)));
		int db = Const.BLOCK_SIZE * d;
		int sx = 0; // mgc.screenWidth() - db;
		int sy = 0;
		mgc.fillRectangle(sx, sy, db, db, COL_BACKGROUND);
		drawIt(false, currentBlock, createBlockPosList(x, y, d, d, sx, sy));
	}

	private int c(int x) {
		return blockSet.compressBlock(x);
	}

	public void showBigPalette(int currentBlock, Coord mouse) {
		int screen = mgc.screenHeight();
		mgc.fillRectangle(0, 0, mgc.screenWidth(), screen, COL_BACKGROUND);

		int vscroll = swm.scrollPosFromScreenPos(mouse.y);
		hoverBlock = -1;
		List<BlockPos> ps = createBlockPosList(0, 0, BLOCKS_PER_LINE, bigBlockPaletteHeight, 0, -vscroll);
		for (BlockPos p : ps) {
			if (mouse.y >= p.y && mouse.y <= p.y + 15 && mouse.x >= p.x && mouse.x <= p.x + 15) {
				hoverBlock = p.b;
			}
		}

		drawIt(true, hoverBlock, ps);
	}

	private void drawIt(boolean labels, int currentBlock, List<BlockPos> ps) {
		currentBlock = c(currentBlock);

		for (BlockPos p : ps) {
			blockSet.draw(p.b, p.x, p.y);
			if (currentBlock == c(p.b)) {
				boolean real = currentBlock == p.b;
				mgc.drawBox(p.x, p.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE,
						mgc.process(real ? COL_CURRENT_BLOCK : COL_HOVER_BLOCK));
			}
			if (currentBlock == p.b) {
				// if (c(currentBlock) == currentBlock) {
				// mgc.drawBox(p.x + 1, p.y + 1, Const.BLOCK_SIZE - 2,
				// Const.BLOCK_SIZE - 2,
				// mgc.process(COL_HOVER_BLOCK));
				// }
				// else {
				// }
				if (labels) {
					mgc.drawText(BLOCKS_PER_LINE * Const.BLOCK_SIZE + 8 * 4, p.y, COL_HOVER_BLOCK,
							String.format("%4d", c(currentBlock)));
				}
			}
		}
	}

	public static int getPaletteDelta(int dx, int dy) {
		return dy * BLOCKS_PER_LINE + dx;
	}

	public int getHoverBlock() {
		return hoverBlock;
	}

	public Coord blockPosition(int currentBlock) {
		int x = currentBlock % BLOCKS_PER_LINE;
		int y = currentBlock / BLOCKS_PER_LINE;
		x *= Const.BLOCK_SIZE;
		y *= Const.BLOCK_SIZE;
		x += Const.BLOCK_SIZE / 2;
		y += Const.BLOCK_SIZE / 2;
		return new Coord(x, swm.screenPosFromCanvasPos(y));
	}
}
