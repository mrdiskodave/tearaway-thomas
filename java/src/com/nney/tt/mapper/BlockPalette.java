package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.Const;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.utils.Math2;

/**
 * Everything about the palettes of map blocks that we display.
 */
public class BlockPalette {
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
	 * retains its meaning.
	 */
	private static final int BLOCKS_PER_LINE = 20;

	/**
	 * Our background colour.
	 */
	private static final int COL_BACKGROUND = 0xff0020ff;

	private static final int CT = 0xff0000;

	private static final int HT = 0x00ff00;

	private final BlocksHolder blocksHolder;
	private final int blockCount;
	private final int bigBlockPaletteHeight;
	private final MapperGC gc;

	private final MapperColors mc;

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

	public BlockPalette(MapperColors mc, MapperGC mapperGC, BlocksHolder blocksHolder) {
		this.mc = mc;
		this.gc = mapperGC;
		this.blocksHolder = blocksHolder;
		this.blockCount = blocksHolder.getBlockCount();
		this.bigBlockPaletteHeight = Math2.roundUpDiv(blockCount, BLOCKS_PER_LINE);
	}

	public void showSmallPalette(int currentBlock) {
		int d = 5;
		int x = Math2.limit(0, BLOCKS_PER_LINE - d, (currentBlock % BLOCKS_PER_LINE) - (d / 2));
		int y = Math2.limit(0, bigBlockPaletteHeight - d, (currentBlock / BLOCKS_PER_LINE - (d / 2)));
		int db = Const.BLOCK_SIZE * d;
		int sx = gc.screenWidth() - db;
		int sy = 0;
		gc.fillRectangle(sx, sy, db, db, COL_BACKGROUND);
		for (BlockPos p : createBlockPosList(x, y, d, d, sx, sy)) {
			blocksHolder.draw(p.b, p.x, p.y);
			if (currentBlock == p.b) {
				gc.drawBox(p.x, p.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, mc.currentBlock());
			}
		}
	}

	public int showBigPalette(int currentBlock, int mouseX, int mouseY) {
		gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), COL_BACKGROUND);

		int protrusion = Math.max(bigBlockPaletteHeight * Const.BLOCK_SIZE - gc.screenHeight(), 0);
		int vscroll = computeVerticalScrollAmount(mouseY, protrusion);
		int hoverBlock = -1;

		for (BlockPos p : createBlockPosList(0, 0, BLOCKS_PER_LINE, bigBlockPaletteHeight, 0, -vscroll)) {
			blocksHolder.draw(p.b, p.x, p.y);
			if (currentBlock == p.b) {
				gc.drawBox(p.x, p.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, mc.currentBlock());
				gc.drawText(BLOCKS_PER_LINE * Const.BLOCK_SIZE, p.y, CT,
						String.format("%4d", currentBlock));
			}
			if (mouseY >= p.y && mouseY <= p.y + 15 && mouseX >= p.x && mouseX <= p.x + 15) {
				hoverBlock = p.b;
				if (hoverBlock == currentBlock) {
					gc.drawBox(p.x + 1, p.y + 1, 14, 14, mc.hoverBlock());
				}
				else {
					gc.drawBox(p.x, p.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, mc.hoverBlock());
				}
				gc.drawText(BLOCKS_PER_LINE * Const.BLOCK_SIZE + 8 * 4, p.y, HT,
						String.format("%4d", hoverBlock));
			}
		}
		return hoverBlock;
	}

	private int computeVerticalScrollAmount(int mousePos, int protrusion) {
		int scrollZoneSize = gc.screenHeight() - 1 - SCROLL_MARGIN * 2;
		int mousePositionWithinScrollZone = Math2.limit(0, scrollZoneSize, mousePos - SCROLL_MARGIN);
		return (protrusion * mousePositionWithinScrollZone) / scrollZoneSize;
	}

	public int getPaletteDelta(int dx, int dy) {
		return dy * BLOCKS_PER_LINE + dx;
	}
}
