package com.nney.tt.tinytools;

public class FractionTracker {
	float f;
	
	public float get() {
		return f;
	}
	
	public int set(float n) {
		int answer = (int) n;
		n -= answer;
		f = n;
		return answer;
	}
}
