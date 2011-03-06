package com.nney;

import java.util.HashMap;
import java.util.List;

public class FrameSource {
	private final HashMap<Frame, Bob> cache = new HashMap<Frame, Bob>();
	private final FrameLoader loader;
	private final FrameFinder finder;

	FrameSource(FrameFinder finder, FrameLoader loader) {
		this.finder = finder;
		this.loader = loader;
	}

	private Bob[] get(List<Frame> frames) {
		Bob[] bobs = new Bob[frames.size()];
		for (int x = 0; x < frames.size(); x++) {
			Frame frame = frames.get(x);
			Bob answer = cachedLoad(frame);
			bobs[x] = answer;
		}
		return bobs;
	}

	private Bob cachedLoad(Frame frame) {
		Bob answer = cache.get(frame);
		if (answer == null) {
			answer = loader.load(frame);
			cache.put(frame, answer);
		}
		else {
			System.out.println(frame.toString());
		}
		return answer;
	}

	// wrap and proxy some 'FrameFinder' methods for our caller's convience 
	
	public void selectInput(String name) {
		finder.selectInput(name);
	}

	public Bob[] next(int i) {
		return get(finder.next(i));
	}

	public Bob[] next() {
		return next(1);
	}

	public Bob[] cycle(int i) {
		return get(finder.cycle(i));
	}
}
