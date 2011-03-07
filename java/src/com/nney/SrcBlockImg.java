package com.nney;

import com.nney.utils.FileOpenable;
import com.nney.utils.OpenableTools;

public class SrcBlockImg {
	private final int blockSize;
	private final int blocksW;
	private final int blockCount;
	private final SimpleImage blocks;

	SrcBlockImg(int blockSize) {
		this.blockSize = blockSize;
		
		String filename = String.format("C:\\Users\\david\\Desktop\\newdata\\blocks\\w.png");
		byte[] someRawGraphicsFile = OpenableTools.load(new FileOpenable(filename));
		blocks = new SimpleImage(someRawGraphicsFile);
		int w = blocks.getWidth();
		int h = blocks.getHeight();
		assert w % blockSize == 0;
		assert h % blockSize == 0;
		blocksW = w / blockSize;
		int blocksH = h / blockSize;
		blockCount = blocksW*blocksH;
	}
	
	SimpleImage getBlock(int b) {
		assert b < blockCount;
		int x = b % blocksW;
		int y = b / blocksW;
		x *= blockSize;
		y *= blockSize;
		return blocks.view(x, y, blockSize, blockSize); 
	}

	public int getBlockCount() {
		return blockCount;
	}
}
