package com.nney.tt.mapper;

public class TopDownStatusLayer extends StatusLayer {
	public TopDownStatusLayer(MapperGC mgc) {
		super(mgc);
	}

	@Override
	protected int computeFirstY() {
		return 0;
	}

	@Override
	protected int computeRow(int row) {
		return row;
	}
}
