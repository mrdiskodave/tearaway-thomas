package com.nney.tt.mapper;

import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

class UndoControler {
	private Stack<UndoRedo> undo = new Stack<UndoRedo>();

	private Stack<UndoRedo> redo = new Stack<UndoRedo>();

	private int mark = -1;

	/**
	 * Add a new action. Any actions waiting to be redone are lost.
	 * 
	 * @param u
	 *            The action to add.
	 */
	public void add(UndoRedo u) {
		if (u == null) {
			throw new InvalidParameterException();
		}
		redo.clear();
		undo.push(u);
	}

	/**
	 * Add a new action. Any actions waiting to be redone are lost. This method
	 * calls {@link UndoRedo#redo()} immediately in order to take the action for
	 * the first time.
	 * 
	 * @param u
	 *            The action to add.
	 */
	public void redoThenAdd(UndoRedo u) {
		if (u == null) {
			throw new InvalidParameterException();
		}
		if (u.redo()) {
			add(u);
		}
		else {
			System.out.println("Nothing changed");
		}
	}
	
	/**
	 * Drop a marker in the undo chain.
	 */
	public void mark() {
		mark = undo.size(); 
	}
	
	/**
	 * Fold all the undo events between the marker and now into a single event.
	 */
	public void fold() {
		assert mark>=0;
		int distance = undo.size()-mark;
		System.out.println("FOLD:"+distance);
		if (distance>1) {
			List<UndoRedo> items = new	ArrayList<UndoRedo>(); 
			while (undo.size()>mark) {
				items.add(undo.pop());
			}
			undo.push(new MetaUndoRedo(items));
		}
		mark = -1;
	}

	/**
	 * Undo the last action. The action's effects can be reinstated by calling
	 * {@link #redo()}. This method can be called repeatedly to undo as many
	 * actions as we have memory for.
	 */
	public void undo() {
		if (!undo.isEmpty()) {
			System.out.println("undo");
			UndoRedo u = undo.pop();
			u.undo();
			redo.push(u);
		}
	}

	/**
	 * Redo the last undo action. The action's effects are reinstated. This
	 * method can be called repeatedly to redo all undone actions <b>unless</b>
	 * the redo "future-history" has been truncated by a call to
	 * {@link #redoThenAdd(UndoRedo)}.
	 */
	public void redo() {
		if (!redo.isEmpty()) {
			System.out.println("redo");
			UndoRedo u = redo.pop();
			u.redo();
			undo.push(u);
		}
	}

	public int size() {
		// just for status display
		return undo.size();
	}
}
