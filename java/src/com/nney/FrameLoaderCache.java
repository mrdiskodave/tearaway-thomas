package com.nney;

import java.util.HashMap;

public class FrameLoaderCache extends FrameLoader {
	private HashMap<SpriteName, Sprite> cache = new HashMap<SpriteName, Sprite>();
	private final FrameLoader target; 

	public FrameLoaderCache(FrameLoader target) {
		this.target = target;
	}
	
	@Override
	public Sprite load(SpriteName frame) {
		Sprite answer = cache.get(frame);
		if (answer == null) {
			answer = target.load(frame);
			cache.put(frame, answer);
		}
		else {
			System.out.println("CACHE HIT FOR:"+frame);
		}
		return answer;
	}
	
	HashMap<SpriteName, Sprite> getSpriteDict() {
		return cache;
	}
}
