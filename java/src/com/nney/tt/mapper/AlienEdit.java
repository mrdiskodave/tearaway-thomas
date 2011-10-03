package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.nney.tt.aliens.Alien;

/**
 * Captures any property-edit to an Alien for undo-redo purposes.
 * 
 * <p>
 * Usage: Construct it on a list of {@link Prop}. Then change those properties
 * (by directly accessing the {@link Alien}. Then call {@link #size()} and if it
 * is non-zero then submit this object to {@link UndoControler#add(UndoRedo)}.
 */
class AlienEdit extends SymmetricalUndoRedo {
	class Content {
		FieldAccessor fa;
		Object content;

		Content(FieldAccessor fa, Object content) {
			this.fa = fa;
			this.content = content;
			System.out.println("Saving " + fa + " = " + content);
		}

		void swap() {
			Object t = fa.getCopy();
			fa.put(content);
			content = t;
		}

		boolean same() {
			return fa.get().equals(content);
		}
	}

	private final List<Content> cs = new ArrayList<Content>();
	private final Alien alien;

	AlienEdit(Alien alien) {
		this.alien = alien;
		for (Prop p : APS.propsForAlien(alien)) {
			FieldAccessor fa = p.getFieldAccessor();
			Object o = fa.getCopy();
			cs.add(new Content(fa, o));
		}
	}

	private void removeMatching() {
		for (Iterator<Content> ci = cs.iterator(); ci.hasNext();) {
			Content c = ci.next();
			if (c.same()) {
				ci.remove();
			}
		}
	}

	/**
	 * How many properties have changed?
	 */
	public int size() {
		removeMatching();
		return cs.size();
	}

	@Override
	protected void swap() {
		for (Content c : cs) {
			c.swap();
		}
		alien.onPropUpdate();
	}
}
