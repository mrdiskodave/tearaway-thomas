package com.nney;

import java.util.ArrayList;
import java.util.List;

public class Anim {
	/**
	 * The animation rate from 256 (every frame) to 1 (every 256 frames) to 0 (never).
	 */
	int rate;
	
	/**
	 * Where we are in the frame list.
	 */
	int pos;
	
	/**
	 * Accumulator used to track how far rate progression towards next frame.
	 */
	int acc;
	
	/**
	 * The frames themselves.
	 */
	List<Frame> frames = new ArrayList<Frame>();
}
