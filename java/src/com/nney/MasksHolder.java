package com.nney;

import com.nney.utils.Openable;

public class MasksHolder {
	final private int blockEdgeLength;
	final private int blockArea;
	final private BitArray maskSettings;

	public MasksHolder(int blockEdgeLength, Openable openable) {
		TemporaryBlockSource t = new TemporaryBlockSource(openable, blockEdgeLength);
		this.blockEdgeLength = blockEdgeLength;
		this.blockArea = blockEdgeLength*blockEdgeLength;
		maskSettings = new BitArray(blockArea*t.getBlockCount());
		
		for (int block=0; block<t.getBlockCount(); block++) {
			SimpleImage si = t.getBlock(block);
			for (int y=0; y<blockEdgeLength; y++) {
				for (int x=0; x<blockEdgeLength; x++) {
					if ((si.getPixel(x, y)&1)==0) {
						maskSettings.set(blockArea*block + y * blockEdgeLength + x);
					}
				}
			}
		}
	}
	
	boolean inTheGround(int block, int x, int y) {
		assert x<blockEdgeLength;
		assert y<blockEdgeLength;
		return maskSettings.test(blockArea*block + y * blockEdgeLength + x);
	}
}
