package com.nney;

public class AnimSpec {
	int rate;
	String[] frameNames;
	
	AnimSpec(int rate, String... frameNames) {
		this.rate = rate;
		this.frameNames = frameNames;
	}
}
