package com.nney.tt.mapper;

public class MapperColors {
	/**
	 * The colour we use to highlight the current block.
	 */
	private static final int COL_CURRENT_BLOCK = 0xffff5555;

	/**
	 * The colour used to highlight the mouse-hovered block.
	 */
	private static final int COL_HOVER_BLOCK = 0xff55ff55;

	private ColorCycle cc = new ColorCycle();

	public int currentBlock() {
		return cc.process(COL_CURRENT_BLOCK);
	}
	
	public int hoverBlock() {
		return cc.process(COL_HOVER_BLOCK);
	}
	
	public void advance() {
		cc.advance();
	}

}
