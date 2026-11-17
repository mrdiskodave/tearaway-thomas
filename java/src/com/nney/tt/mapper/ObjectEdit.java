package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.nney.tt.aliens.Alien;
import com.nney.tt.props.HasProps;
import com.nney.tt.props.OPS;
import com.nney.tt.props.Prop;

/**
 * Captures any property-edit to an Alien for undo-redo purposes.
 * 
 * <p>
 * Usage: Construct it on a list of {@link Prop}. Then change those properties
 * (by directly accessing the {@link Alien}. Then call {@link #size()} and if it
 * is non-zero then submit this object to {@link UndoControler#add(UndoRedo)}.
 */
class ObjectEdit extends SymmetricalUndoRedo {
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

	private final List<Content> cs = new ArrayList<>();
	private final HasProps object;

	ObjectEdit(HasProps object) {
		this.object = object;
		for (Prop p : OPS.propsFor(object)) {
			FieldAccessor fa = p.getFieldAccessor();
			Object o = fa.getCopy();
			cs.add(new Content(fa, o));
		}
	}

	public void removeMatching() {
		for (Iterator<Content> ci = cs.iterator(); ci.hasNext();) {
			Content c = ci.next();
			if (c.same()) {
				ci.remove();
			}
		}
	}

	@Override
	protected boolean swap() {
		if (cs.isEmpty()) return false;
		for (Content c : cs) {
			c.swap();
		}
		object.onPropUpdate();
		return true;
	}

	HasProps beingEditted() {
		return object;
	}
}
