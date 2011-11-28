package com.nney.tt.map;

import com.nney.tt.Const;
import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.gfx.SimpleImage.ChangePixel;

public final class MasksHolder {
	private static final boolean CTC_COLOURED_MASK = true;
	final private BitArray maskSettings;

	public MasksHolder(SimpleImage msi) {
		for (int c : msi.collectPalette()) {
			System.out.println(String.format("mask colour %08x", c));
		}

		BlockSource t = new BlockSource(msi, Const.BLOCK_SIZE);
		maskSettings = new BitArray(Const.BLOCK_SIZE * Const.BLOCK_SIZE * t.getBlockCount());

		for (int block = 0; block < t.getBlockCount(); block++) {
			SimpleImage si = t.getBlock(block);
			for (int y = 0; y < Const.BLOCK_SIZE; y++) {
				for (int x = 0; x < Const.BLOCK_SIZE; x++) {
					boolean itg = colourTest(si.get(x, y));
					if (itg) {
						maskSettings.set(pos(block, x, y));
					}
					// self test
					assert inTheGround(block, x, y) == itg;
				}
			}
		}
		System.out.println(String.format("Masks: %s/%s", maskSettings.count(), maskSettings.length()));
	}

	private static boolean colourTest(int c) {
		return c == 0xff000000;
	}

	public boolean inTheGround(int block, int x, int y) {
		assert x < Const.BLOCK_SIZE;
		assert y < Const.BLOCK_SIZE;
		// pixelTest is inlined here:
		return maskSettings.test(((((block << Const.BLOCK_SHIFT) + y) << Const.BLOCK_SHIFT) + x));
	}

	private int pos(int block, int x, int y) {
		return (((block << Const.BLOCK_SHIFT) + y) << Const.BLOCK_SHIFT) + x;
	}

	public static SimpleImage renderMask(SimpleImage msi, SimpleImage originalBsi) {
		if (CTC_COLOURED_MASK) {
			SimpleImage bsi = originalBsi.copy();
			int w = bsi.width();
			int h = bsi.height();
			assert w == msi.width();
			assert h == msi.height();
			for (int y = 0; y < h; y++) {
				for (int x = 0; x < w; x++) {
					if (colourTest(msi.get(x, y))) {
						bsi.put(x, y, 0xffff00ff);
					}
				}
			}
			return bsi;
		}
		else {
			SimpleImage bsi = msi.copy();
			bsi.changePixels(new ChangePixel() {
				@Override
				public int change(int col) {
					if (colourTest(col)) {
						// how we want to display ground?
						return 0xff000000;
					}
					// how we want to display sky?
					return 0;
				}
			});
			return bsi;
		}
	}
}
