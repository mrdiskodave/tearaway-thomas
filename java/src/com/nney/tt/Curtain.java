package com.nney.tt;

/**
 * Sometimes it is useful to hide the screen contents.
 * Curtains can be used for this. 
 */
public interface Curtain {
	/**
	 * A state value representing an open curtain
	 * i.e. one that does not obscure anything on the screen.
	 */
	int OPEN = 1;
	
	/**
	 * A state value representing a closed curtain
	 * i.e. one that obscures everything on the screen.
	 */
	int CLOSED = 2;

	/**
	 * Tell the curtain where to move to.
	 * 
	 * @param state
	 *            Either {@link #OPEN} or {@link #CLOSED}.
	 */
	void target(int state);

	/**
	 * Ask where the curtain is set to move to.
	 * 
	 * @return Either {@link #OPEN} or {@link #CLOSED}.
	 */
	int target();

	/**
	 * Has the curtain arrive at it's target yet?
	 * 
	 * @return <code>true</code> "it has" or <code>false</code> "it has not".
	 */
	boolean isDone();

	/**
	 * Set the current state of the curtain. If the curtain is in a visible
	 * state of transition this may cause it to jump, before the viewers eyes,
	 * into another state. Because of this this method should be called with
	 * care.
	 * 
	 * @param state Either {@link #OPEN} or {@link #CLOSED}.
	 */
	void current(int state);

	/**
	 * Update the internal state of this curtain.
	 */
	void update();

	/**
	 * Render this curtain onto the screen.
	 */
	void draw();
}
