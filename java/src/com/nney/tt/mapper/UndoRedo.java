package com.nney.tt.mapper;

/**
 * An action that may need to be done (and then undone or redone repeatedly).
 */
public interface UndoRedo {
	/**
	 * Do the action.
	 */
	boolean redo();

	/**
	 * Undo the action.
	 */
	void undo();

}
