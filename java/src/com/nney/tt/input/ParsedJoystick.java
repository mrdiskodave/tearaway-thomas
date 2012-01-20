package com.nney.tt.input;

public interface ParsedJoystick {
	/**
	 * Get joystick X movement.
	 * 
	 * @return <code>-1</code> for left, <code>1</code> for right,
	 *         <code>0</code> for neither.
	 */
	int x();

	/**
	 * Get joystick Y movement.
	 * 
	 * @return <code>-1</code> for up, <code>1</code> for down, <code>0</code>
	 *         for neither.
	 */
	int y();

	/**
	 * Is the fire button pressed on the joystick?
	 * 
	 * @return <code>true</code> meaning "it is" or <code>false</code> meaning
	 *         "it is not".
	 */
	boolean fire();
}