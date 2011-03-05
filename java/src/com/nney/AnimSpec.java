package com.nney;

public class AnimSpec {
	int defaultRate;
	FramesSpec[] frameNames;
	
	AnimSpec(int defaultRate, FramesSpec... frameNames) {
		this.defaultRate = defaultRate;
		this.frameNames = frameNames;
	}
}
