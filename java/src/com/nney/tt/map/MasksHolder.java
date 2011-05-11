package com.nney.tt.map;

import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.SimpleImage;
import com.nney.utils.Openable;

public class MasksHolder {
	final private int blockSize;
	final private int blockArea;
	final private BitArray maskSettings;

	public MasksHolder(int blockSize, Openable openable) {
		BlockSource t = new BlockSource(openable, blockSize);
		this.blockSize = blockSize;
		this.blockArea = blockSize*blockSize;
		maskSettings = new BitArray(blockArea*t.getBlockCount());
		
		for (int block=0; block<t.getBlockCount(); block++) {
			SimpleImage si = t.getBlock(block);
			for (int y=0; y<blockSize; y++) {
				for (int x=0; x<blockSize; x++) {
					if ((si.getPixel(x, y)&1)==0) {
						maskSettings.set(blockArea*block + y * blockSize + x);
					}
				}
			}
		}
	}
	
	public boolean inTheGround(int block, int x, int y) {
		assert x<blockSize;
		assert y<blockSize;
		return maskSettings.test(blockArea*block + y * blockSize + x);
	}
}
