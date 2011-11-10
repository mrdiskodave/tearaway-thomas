package com.nney.tt.mapper;

public class BottomUpStatusLayer extends StatusLayer {
	public BottomUpStatusLayer(MapperGC mgc) {
		super(mgc);
	}

	@Override
	protected int computeFirstY() {
		return screenHeightInPixels - (screenHeightInCharacters * characterHeightInPixels);
	}

	@Override
	protected int computeRow(int row) {
		return screenHeightInCharacters - 1 - row;
	}
}
