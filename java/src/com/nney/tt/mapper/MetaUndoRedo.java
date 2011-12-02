package com.nney.tt.mapper;

import java.util.List;

import com.nney.utils.ListUtil;

public class MetaUndoRedo implements UndoRedo {
	private final List<UndoRedo> items;

	public MetaUndoRedo(List<UndoRedo> items) {
		this.items = items;
	}

	@Override
	public boolean redo() {
		boolean doneSomething = false;
		for (UndoRedo item : ListUtil.reversed(items)) {
			doneSomething |= item.redo();
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
