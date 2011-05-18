package com.nney.tt.sprites;

public class Anim {
	public static final int MAX_RATE = 256;

	final public int defaultRate;
	final public Sprite[] frames;
	final public int repeatPos;
	final public String name;

	Anim(int defaultRate, Sprite[] frames, int repeatPos, String name) {
		this.defaultRate = defaultRate;
		this.frames = frames;
		this.repeatPos = repeatPos;
		this.name = name;
	}
}
