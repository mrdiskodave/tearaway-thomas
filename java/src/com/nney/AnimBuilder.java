package com.nney;

import java.util.ArrayList;
import java.util.List;

public class AnimBuilder {
	// our internal state ... very much like the first fields in a Frame
	private String name;
	private int number;
	
	private List<Frame> frames = new ArrayList<Frame>();
	private int rate;
	private boolean repeat;
	private int fx;

	final private FrameLoader frameLoader;

	public AnimBuilder(FrameLoader frameLoader) {
		this.frameLoader = frameLoader;
	}

	public Anim build() {
		System.out.println("DONE");
		Bob[] bobs = new Bob[frames.size()];
		for (int x=0; x<bobs.length; x++) {
			System.out.println(frames.get(x));
			bobs[x] = frameLoader.load(frames.get(x));
		}
		Anim answer = new Anim(rate, bobs, repeat);
		reset();
		return answer;
	}

	private void reset() {
		frames.clear();
		rate = 0;
		repeat = false;
		fx = 0;
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
			frames.add(new Frame(name, number, fx));
			number++;
		} while (--howMany>0);
		return this;
	}

	public AnimBuilder copy(Anim other) {
		for (Bob bob : other.bobs) {
			Frame frame = bob.frame;
			frames.add(new Frame(frame.name, frame.number, fx));
		}
		rate = other.rate;
		repeat = other.repeat;
		return this;
	}

	public AnimBuilder reverse() {
		List<Frame> f = frames;
		frames = new ArrayList<Frame>();
		for (int x=f.size(); --x>=0;) {
			frames.add(f.get(x));
		}
		return this;
	}
	
	public AnimBuilder next() {
		return next(1);
	}
	
	public AnimBuilder fx(int x) {
		fx |= x;
		return this;
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

	public AnimBuilder otherWayTo(Anim anim) {
		return fx(BobFX.MIRROR).copy(anim).reverse();
	}
}
