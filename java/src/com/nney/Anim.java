package com.nney;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.nney.utils.FileOpenable;
import com.nney.utils.Openable;
import com.nney.utils.Pump;

public class Anim {
	/**
	 * The animation rate from 256 (every frame) to 1 (every 256 frames) to 0
	 * (never).
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
	Bob[] frames;
	
	Bob next() {
		acc += rate;
		if (acc>256) {
			acc -= 256;
			pos += 1;
			if (pos>=frames.length) {
				System.out.println("Wrap");
				pos = 0;
			}
		}
		System.out.println("Frame"+Integer.toString(pos));
		return frames[pos];
	}

	Anim(int rate, Bob[] frames) {
		this.rate = rate;
		this.frames = frames;
	}
}
