package com.nney.tt.sprites;

import com.nney.tt.geom.Box;
import com.nney.tt.gfx.Disposable;
import com.nney.utils.Math2;

public final class Anim implements Disposable {
	public static final int MAX_RATE = 256;

	final public int defaultRate;
	final public Sprite[] sprites;
	final public int repeatPos;
	final public String name;

	Anim(int defaultRate, Sprite[] frames, int repeatPos, String name) {
		this.defaultRate = defaultRate;
		this.sprites = frames;
		this.repeatPos = repeatPos;
		this.name = name;
	}
	
	public Box box() {
		Box b = sprites[0].box();
		for (int x=1; x<sprites.length; x++) {
			b.accommodate(sprites[x].box());
		}
		return b;
	}
	
	public Sprite randomAccessByFrameNumber(int rate, int f) {
		f *= rate;
		f /= Anim.MAX_RATE;
		if (f<sprites.length) return sprites[f];
		return null;
	}

	public int lengthInFrames(int rate) {
		return Math2.roundUpDiv(Anim.MAX_RATE*sprites.length, rate);
	}
	
	
	public Sprite randomAccessByFrameNumber(int f) {
		return randomAccessByFrameNumber(defaultRate, f);
	}

	public int lengthInFrames() {
		return lengthInFrames(defaultRate);
		
	}

	@Override
	public void dispose() {
		for (Sprite sprite: sprites) {
			sprite.dispose();
		}
	}
}
