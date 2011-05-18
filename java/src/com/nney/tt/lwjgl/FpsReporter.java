package com.nney.tt.lwjgl;

import org.lwjgl.opengl.Display;

public class FpsReporter {
	private final int count;
	private int counter;
	private long lastTime = System.nanoTime();

	public FpsReporter(int count) {
		this.count = count;
	}

	public void reportFps() {
		counter++;
		if (counter == count) {
			counter = 0;
			long past = lastTime;
			long present = System.nanoTime();

			float diff = present - past;
			diff /= 1000000000;
			float actual_fps = (float) count / diff;
			Display.setTitle("FPS: " + actual_fps);

			lastTime = System.nanoTime();
			// not "= present" in case it took a while to setTitle()
		}
	}

}
