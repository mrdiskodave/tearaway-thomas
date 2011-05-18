package com.nney.tt.mapper;

import java.util.Stack;

class UndoControler {
	private Stack<DoUndo> undo = new Stack<DoUndo>();

	private Stack<DoUndo> redo = new Stack<DoUndo>();

	/**
	 * Add a new action. Any actions waiting to be redone are lost. This method
	 * calls {@link DoUndo#redo()} immediately in order to take the action for
	 * the first time.
	 * 
	 * @param u
	 *            The action to add.
	 * 
	 * @see DoUndo
	 */
	public void add(DoUndo u) {
		if (u != null) {
			System.out.println("adding undo (redoing first!)");
			u.redo();
			redo.clear();
			undo.push(u);
		}
	}

	/**
	 * Undo the last action. The action's effects can be reinstated by calling
	 * {@link #redo()}. This method can be called repeatedly to undo as many
	 * actions as we have memory for.
	 */
	public void undo() {
		if (!undo.isEmpty()) {
			System.out.println("undo");
			DoUndo u = undo.pop();
			u.undo();
			redo.push(u);
		}
	}

	/**
	 * Redo the last undo action. The action's effects are reinstated. This
	 * method can be called repeatedly to redo all undone actions <b>unless</b>
	 * the redo "future-history" has been truncated by a call to
	 * {@link #add(DoUndo)}.
	 */
	public void redo() {
		if (!redo.isEmpty()) {
			System.out.println("redo");
			DoUndo u = redo.pop();
			u.redo();
			undo.push(u);
		}
	}
}
