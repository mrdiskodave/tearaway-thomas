package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;

public abstract class Pen {
	public PenServices srv;
	public boolean active;

	/**
	 * An opportunity for the this object to draw any graphics on screen that it
	 * needs to for status-display etc (independent of the location of the
	 * pointer).
	 */
	void presentation() {
	}

	/**
	 * Does this object work with world coordinates or screen coordinates?
	 * 
	 * @return <code>true</code> meaning "world coordinates" or
	 *         <code>false</code> meaning "screen coordinates". This changes all
	 *         the {@link Coord} parameters given to other methods.
	 */
	boolean usesWorldCoords() {
		return true;
	}

	/**
	 * What key activates us?
	 * 
	 * @return A key number. This could from {@link Pointer} or from
	 *         {@link Keyboard} as both work.
	 */
	abstract int key();

	/**
	 * Respond to the mouse moving around without the {@link #key()} down.
	 * 
	 * @param c
	 *            Where is the mouse pointer?
	 */
	void hover(Coord c) {
	}

	/**
	 * Respond to the {@link #key()} being pushed down.
	 * 
	 * @param c
	 *            Where is the mouse pointer?
	 * @return Continue to pass this event long the {@link Pen} chain?
	 */
	boolean down(Coord c) {
		return true;
	}

	/**
	 * Respond to the mouse moving around with the {@link #key()} down.
	 * 
	 * @param c
	 *            Where is the mouse pointer?
	 */
	void stroke(Coord c) {
	}

	/**
	 * Respond to the release of the {@link #key()}.
	 * 
	 * @param c
	 *            Where is the mouse pointer?
	 */
	void up(Coord c) {
	}
}
