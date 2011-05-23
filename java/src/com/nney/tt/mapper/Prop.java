package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Coord;

public abstract class Prop {
	protected final AlienProp aprop;
	protected final FieldAccessor fa;

	public Prop(AlienProp aprop, FieldAccessor fa) {
		this.aprop = aprop;
		this.fa = fa;
	}

	public Coord[] getBats(Coord alien) {
		return null;
	}

	/**
	 * Generate this properties bats.
	 * @param bt
	 *            A destination for the bats (and also somewhere to render other
	 *            visual hints about this {@link Prop}).
	 */
	void drawAuxBatStuff(BatGC bt) {}

	/**
	 * Respond to a bat movement.
	 * 
	 * @param what
	 *            A bat number where <code>0</code> is the first bat sent to the
	 *            {@link BatGC} by {@link #drawAuxBatStuff(BatGC)} and
	 *            they number upward from there.
	 * @param where
	 *            Where the user is trying to move the bat to (in world
	 *            coordinates).
	 */
	void onBatMovement(int what, Coord where) {
		// shouldn't be called on things that don't know how to respond to it
		assert false;
	}

	String[] createButtons() {
		return null;
	}

	void onButtonPress(int what, ButtonPressServices bps) {
		// shouldn't be called on things that don't know how to respond to it
		assert false;
	}

	public String name() {
		return aprop.name();
	}

	public String doc() {
		return aprop.doc();
	}

	abstract public String text();
	
	public String getUniqueName() {
		return fa.fieldName();
	}

	public void tellPosition(Coord ourPosition) {
		// shouldn't be called on things that don't know how to respond to it
		assert false;
	}
	
	public void copyFrom(Prop other) {
		fa.put(other.fa.getCopy());
	}

}
