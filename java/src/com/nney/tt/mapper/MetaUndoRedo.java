package com.nney.tt.mapper;

import java.util.List;

public class MetaUndoRedo implements UndoRedo {
	private final List<UndoRedo> items;

	public MetaUndoRedo(List<UndoRedo> items) {
		this.items = items;
	}

	@Override
	public boolean redo() {
		boolean doneSomething = false;
		int x = items.size();
		while (--x >= 0) {
			doneSomething |= items.get(x).redo();
		}
		return doneSomething;
	}

	@Override
	public void undo() {
		for (UndoRedo item : items) {
			item.undo();
		}
	}

}
