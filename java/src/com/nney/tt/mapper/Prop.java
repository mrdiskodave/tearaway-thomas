package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public abstract class Prop {
	private PropPack pp;

	public Prop(PropPack pp) {
		this.pp = pp;
	}
	
	public Coord alienPos() {
		return pp.alien().c;
	}

	public FieldAccessor getFieldAccessor() {
		return pp.access();
	}
	
	public String name() {
		return pp.getAnn().name();
	}

	public String doc() {
		return pp.getAnn().doc();
	}

	abstract public String text();
	
	public void copyFrom(Prop other) {
		pp.access().put(other.pp.access().getCopy());
	}
	
	// ---------------------------------------------------------------------------
	// TEXT UI 
	
	String[] createButtons() {
		return null;
	}

	void onButtonPress(int what, ButtonPressServices bps) {
		// shouldn't be called on things that don't know how to respond to it
		assert false;
	}

	// ---------------------------------------------------------------------------
	// GRAPHICAL UI 

	public Coord[] getBats() {
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
	
	public void moveBy(Coord delta) {
	}
}
