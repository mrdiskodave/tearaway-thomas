package com.nney;

import com.nney.utils.Openable;

public class MasksHolder {
	private int[] masks;
	private int blockSize;
	private int blockPixels;
	private int wordsPerBlock;

	public MasksHolder(int blockSize, Openable openable) {
		TemporaryBlockSource t = new TemporaryBlockSource(openable, blockSize);
		blockPixels = blockSize*blockSize;
		this.blockSize = blockSize;
		
		wordsPerBlock = blockPixels/32;
		masks = new int[wordsPerBlock*t.getBlockCount()];
		
		for (int block=0; block<t.getBlockCount(); block++) {
			SimpleImage si = t.getBlock(block);
			for (int y=0; y<blockSize; y++) {
				for (int x=0; x<blockSize; x++) {
					if ((si.getPixel(x, y)&1)==0) {
						int bit = wordsPerBlock*block + y * blockSize + x;
						int offset = bit>>5;
						int mask   = 1<<(bit&31);
						masks[offset] |= mask;
					}
				}
			}
		}
	}
	
	boolean test(int block, int x, int y) {
		assert x<blockSize;
		assert y<blockSize;

		int bit = wordsPerBlock*block + y * blockSize + x;
		int offset = bit>>5;
		int mask   = 1<<(bit&31); 

		return (masks[offset]&mask)!=0;
	}
}
