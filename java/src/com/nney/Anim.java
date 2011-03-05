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
	List<Bob> frames = new ArrayList<Bob>();
	
	Bob next() {
		acc += pos;
		if (acc>256) {
			acc -= 256;
			pos += 1;
			if (pos>=frames.size()) {
				pos = 0;
			}
		}
		return frames.get(pos);
	}

	Anim(int rate, String descr) {
		this.rate = rate;

		String name = null;
		for (String item : descr.split(",")) {
			try {
				int frameNo = Integer.parseInt(item);

				// load name/frameNo as a Bob into frames
				// ---
				// TODO: pluggable?
				String filename = "C:\\Users\\david\\Desktop\\newdata\\bobs\\" + name + "_"
				+ Integer.toString(frameNo) + ".png";
				Openable openable = new FileOpenable(filename);
				byte[] data;
				try {
					data = Pump.loadIntoByteArray(openable);
				}
				catch (IOException e) {
					throw new RuntimeException(e);
				}
				Bob answer = Bob.fromLargeImage(data);
				// ---
				frames.add(answer);
			}
			catch (NumberFormatException e) {
				name = item;
			}
		}

	}
}
