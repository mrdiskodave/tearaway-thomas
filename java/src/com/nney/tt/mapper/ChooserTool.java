package com.nney.tt.mapper;

public class ChooserTool extends Tool {
	public ChooserTool(Mapper parent) {
		super(parent);
	}

	@Override
	boolean ownScreen() {
		return true;
	}

	@Override
	void run() {
		parent.blockChoosingMode();
		parent.showBlocks();
	}
}
