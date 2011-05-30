package com.nney.tt.mapper;

public class BlockChooserTool extends Tool {
	public BlockChooserTool(Mapper parent) {
		super(parent);
	}

	@Override
	boolean ownScreen() {
		return true;
	}

	@Override
	void run() {
		srv.blockChoosingMode();
	}
}
