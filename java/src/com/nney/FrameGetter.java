package com.nney;

import java.util.HashMap;
import java.util.List;

public class FrameGetter {
	private final FrameLoader loader;
	private final FrameRenderer render;
	private final HashMap<Frame, Bob> cache = new HashMap<Frame, Bob>(); 

	FrameGetter(FrameLoader loader, FrameRenderer render) {
		this.loader = loader;
		this.render = render;
	}
	
	Bob[] get(List<Frame> frames) {
		Bob[] bobs = new Bob[frames.size()];
		for (int x=0; x<frames.size(); x++) {
			Frame frame = frames.get(x);
			Bob answer = cachedLoad(frame);
			bobs[x] = answer;
		}
		return bobs;
	}

	private Bob cachedLoad(Frame frame) {
		Bob answer = cache.get(frame);
		if (answer==null) {
			byte[] data = loader.load(frame);
			answer = render.render(data);
			cache.put(frame, answer);
		}
		else {
			System.out.println(frame.toString());
		}
		return answer;
	}
}
