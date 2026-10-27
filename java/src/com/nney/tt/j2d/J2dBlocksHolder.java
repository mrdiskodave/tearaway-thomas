package com.nney.tt.j2d;

import java.awt.Graphics2D;
import java.awt.image.BufferedImage;

import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.BlocksHolder;

/**
 * The map's background blocks, one small image per block. Entirely
 * transparent blocks are stored as <code>null</code> and skipped.
 */
final class J2dBlocksHolder implements BlocksHolder {
	private final J2dGraphicsContext gc;
	private final BufferedImage[] blocks;
	private final int blockSize;

	J2dBlocksHolder(J2dGraphicsContext gc, BlockSource bs) {
		this.gc = gc;
		blockSize = bs.getBlockSize();
		blocks = new BufferedImage[bs.getBlockCount()];
		for (int b = 0; b < blocks.length; b++) {
			if (!bs.isEntirely(b, 0)) {
				blocks[b] = J2dImage.toBufferedImage(bs.getBlock(b));
			}
		}
	}

	@Override
	public void draw(int block, int dx, int dy) {
		if (block < 0 || block >= blocks.length) return;
		BufferedImage bi = blocks[block];
		if (bi != null) gc.g().drawImage(bi, dx, dy, null);
	}

	@Override
	public void draw(int[] row, int dx, int dy) {
		Graphics2D g = gc.g();
		for (int b : row) {
			if (b >= 0 && b < blocks.length) {
				BufferedImage bi = blocks[b];
				if (bi != null) g.drawImage(bi, dx, dy, null);
			}
			dx += blockSize;
		}
	}

	@Override
	public int getBlockCount() {
		return blocks.length;
	}

	@Override
	public void dispose() {
		for (BufferedImage bi : blocks) {
			if (bi != null) bi.flush();
		}
	}
}
