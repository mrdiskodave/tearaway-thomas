package com.nney.tt.mapper;

public abstract class SymmetricalUndoRedo implements UndoRedo {
	@Override
	public boolean redo() {
		return swap();
	}

	@Override
	public void undo() {
		swap();

	}

	abstract protected boolean swap();
}
