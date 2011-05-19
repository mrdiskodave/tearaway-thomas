package com.nney.tt.mapper;

public abstract class SymmetricalUndoRedo implements UndoRedo {
	@Override
	public void redo() {
		swap();
	}

	@Override
	public void undo() {
		swap();

	}

	abstract protected void swap();
}
