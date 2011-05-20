package com.nney.tt.mapper;

public class BottomUpStatusLayer extends StatusLayer {
	public BottomUpStatusLayer(MapperGC mgc) {
		super(mgc);
	}

	@Override
	protected int computeFirstY() {
		return shp - (shc * chp);
	}

	@Override
	protected int computeRow(int row) {
		return shc - 1 - row;
	}
}
