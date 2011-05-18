package com.nney.tt.mapper;

import java.util.Stack;

class UndoControler {
	private Stack<UndoRedo> undo = new Stack<UndoRedo>();

	private Stack<UndoRedo> redo = new Stack<UndoRedo>();

	public void addUndo(UndoRedo u) {
		if (u != null) {
			System.out.println("added undo");
			undo.push(u);
			redo.clear();
		}
	}

	public void undo() {
		if (!undo.isEmpty()) {
			System.out.println("undo");
			UndoRedo u = undo.pop();
			u.swap();
			redo.push(u);
		}
	}

	public void redo() {
		if (!redo.isEmpty()) {
			System.out.println("redo");
			UndoRedo u = redo.pop();
			u.swap();
			undo.push(u);
		}
	}
}
