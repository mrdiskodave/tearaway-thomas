package com.nney;

import java.util.HashMap;

public class FrameLoaderCache implements FrameLoader {
	private HashMap<Frame, Bob> cache = new HashMap<Frame, Bob>();
	private final FrameLoader target; 

	public FrameLoaderCache(FrameLoader target) {
		this.target = target;
	}
	
	@Override
	public Bob load(Frame frame) {
		Bob answer = cache.get(frame);
		if (answer == null) {
			answer = target.load(frame);
			cache.put(frame, answer);
		}
		else {
			System.out.println("CACHE HIT FOR:"+frame);
		}
		return answer;
	}
}
