package com.nney.tt.map;

import com.nney.tt.Const;
import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.SimpleImage;

public final class MasksHolder {
	final private BitArray maskSettings;

	public MasksHolder(SimpleImage msi) {
		BlockSource t = new BlockSource(msi, Const.BLOCK_SIZE);
		maskSettings = new BitArray(Const.BLOCK_SIZE * Const.BLOCK_SIZE * t.getBlockCount());

		for (int block = 0; block < t.getBlockCount(); block++) {
			SimpleImage si = t.getBlock(block);
			for (int y = 0; y < Const.BLOCK_SIZE; y++) {
				for (int x = 0; x < Const.BLOCK_SIZE; x++) {
					boolean itg = pixelTest(si, y, x);
					if (itg) {
						maskSettings.set(pos(block, x, y));
					}
					// self test
					assert inTheGround(block, x, y)==itg;
				}
			}
		}
	}

	private static boolean pixelTest(SimpleImage si, int y, int x) {
		return si.get(x, y)==0xff000000;
	}

	public boolean inTheGround(int block, int x, int y) {
		assert x < Const.BLOCK_SIZE;
		assert y < Const.BLOCK_SIZE;
		// pixelTest is inlined here:
		return maskSettings.test(((((block << Const.BLOCK_SHIFT) + y )<< Const.BLOCK_SHIFT) + x));
	}

	private int pos(int block, int x, int y) {
		return (((block << Const.BLOCK_SHIFT) + y )<< Const.BLOCK_SHIFT) + x;
	}
}
