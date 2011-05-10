package com.nney.tt;

public class MapDrawingInfo {
	public final int initialPixelDestination;
	public final int mapSourceInBlocks;
	public final int screenSizeInBlocks;

	public MapDrawingInfo(int mapSourceInPixels, int screenSizeInPixels, int mapSizeInPixels) {
		initialPixelDestination = -(mapSourceInPixels & Main.BLOCK_MASK);
		mapSourceInBlocks = mapSourceInPixels/Main.BLOCK_SIZE;
		int screenSizeInBlocks0 = TTMath.roundUpDiv(screenSizeInPixels, Main.BLOCK_SIZE);
		
		if (initialPixelDestination + screenSizeInBlocks0*Main.BLOCK_SIZE<screenSizeInPixels) {
			screenSizeInBlocks0++;
		}
//		int mapSizeInBlocks = mapSizeInPixels/Main.BLOCK_SIZE;
//		if (mapSourceInBlocks+screenSizeInBlocks0 < mapSizeInBlocks) {
//			screenSizeInBlocks0++;
//		}
		
		screenSizeInBlocks = screenSizeInBlocks0;
	}
}
