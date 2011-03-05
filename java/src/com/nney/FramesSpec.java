package com.nney;

public class FramesSpec {
	public final String resourceName;
	public final int[] frameNumbers;

	FramesSpec(String resourceName, int... frameNumbers) {
		this.resourceName = resourceName;
		this.frameNumbers = frameNumbers;
		
	}
}
