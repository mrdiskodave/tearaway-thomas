package com.nney.tt.mapper;

/**
 * An action that may need to be done (and then undone or redone repeatedly).
 * Calls to this interface alternate between {@link #redo()} and {@link #undo()}
 * .
 */
public interface DoUndo {
	/**
	 * Do the action.
	 * 
	 * This method is called when the event is first submitted to
	 * {@link UndoControler#add(DoUndo)} in order to take the action for the
	 * first time. This saves the caller the duplicate work of first taking the
	 * action and <b>then</b> crafting an {@link DoUndo} object who's
	 * {@link #redo()} method also takes the action.
	 */
	void redo();

	/**
	 * Undo the action.
	 */
	void undo();

}
