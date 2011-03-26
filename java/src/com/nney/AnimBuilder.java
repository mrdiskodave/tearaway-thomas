package com.nney;

import java.util.ArrayList;
import java.util.List;

public class AnimBuilder {
	// our internal state ... very much like the first fields in a Frame
	private String name;
	private int number;
	
	private List<SpriteName> frames = new ArrayList<SpriteName>();
	private int rate;
	private boolean repeat;

	public Anim build() {
		System.out.println("DONE");
	
//		Sprite[] bobs = new Sprite[frames.size()];
//		for (int x=0; x<bobs.length; x++) {
//			System.out.println(frames.get(x));
//			bobs[x] = frameLoader.load(frames.get(x));
//		}
	
		SpriteName[] framesArr = (SpriteName[]) frames.toArray(new SpriteName[frames.size()]);
		Anim answer = new Anim(rate, framesArr, repeat);
		reset();
		return answer;
	}

	private void reset() {
		frames.clear();
		rate = 0;
		repeat = false;
	}

	public AnimBuilder skip(int distance) {
		number += distance;
		return this;
	}

	public AnimBuilder select(String name) {
		this.name = name;
		number = 0;
		return this;
	}

	public AnimBuilder next(int howMany) {
		do {
			frames.add(new SpriteName(name, number));
			number++;
		} while (--howMany>0);
		return this;
	}

//	public AnimBuilder copy(Anim other) {
//		for (Sprite bob : other.bobs) {
//			frames.add(frame);
//		}
//		rate = other.defaultRate;
//		repeat = other.repeat;
//		return this;
//	}
//
//	public AnimBuilder reverse() {
//		List<SpriteName> f = frames;
//		frames = new ArrayList<SpriteName>();
//		for (int x=f.size(); --x>=0;) {
//			frames.add(f.get(x));
//		}
//		return this;
//	}
	
	public AnimBuilder next() {
		return next(1);
	}
	
	public AnimBuilder rate(int x) {
		rate = x;
		return this;
	}
	
	public AnimBuilder cycle() {
		// add the frames to reverse the cycle need not repeat start or end of cycle
		int p = frames.size() - 2;
		for (int x = 0; x < p; x++) {
			frames.add(frames.get(p - x));
		}
		return this;
	}
	
	public AnimBuilder repeat() {
		repeat = true;
		return this;
	}
}
