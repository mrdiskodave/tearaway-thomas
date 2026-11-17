package com.nney.tt.sprites;

import java.util.ArrayList;

import com.nney.tt.Bounded;
import com.nney.tt.BoundedUtils;
import com.nney.tt.geom.Box;
import com.nney.tt.gfx.Disposable;
import com.nney.utils.Math2;

public final class Anim implements Disposable, Bounded {
	public static final int MAX_RATE = 256;

	final public int defaultRate;
	final Sprite[] sprites;
	final public int repeatPos;
	final public String name;

	Anim(int defaultRate, Sprite[] frames, int repeatPos, String name) {
		this.defaultRate = defaultRate;
		this.sprites = frames;
		this.repeatPos = repeatPos;
		this.name = name;
	}

	public Sprite firstSprite() {
		return sprites[0];
	}

	public Sprite getSprite(int x) {
		return sprites[x];
	}

	@Override
	public Box getBounds() {
		// "sprites" isn't a list
		// make it into one?
		// no getBounds() isn't called on any fast paths
		ArrayList<Sprite> s = new ArrayList<>();
		for (Sprite sprite : sprites) {
			s.add(sprite);
		}

		Box answer = BoundedUtils.collect(s);
		assert answer != null;
		return answer;
	}

	public Sprite randomAccessByFrameNumber(int rate, int f) {
		f *= rate;
		f /= Anim.MAX_RATE;
		if (f < sprites.length) return sprites[f];
		return null;
	}

	public int lengthInFrames(int rate) {
		return Math2.roundUpDiv(Anim.MAX_RATE * sprites.length, rate);
	}

	public Sprite randomAccessByFrameNumber(int f) {
		return randomAccessByFrameNumber(defaultRate, f);
	}

	public int lengthInFrames() {
		return lengthInFrames(defaultRate);

	}

	@Override
	public void close() {
		for (Sprite sprite : sprites) {
			sprite.close();
		}
	}
}
