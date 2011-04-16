package com.nney.tt;

public class MovementSlicer {
	private int kipper;

	MovementSlicer(int m) {
		this.kipper = m;
	}
	
	int next(int sliceSize) {
		if (sliceSize<=0) {
			throw new IllegalArgumentException();
		}
		int answer;
		if (kipper==0) {
			answer = 0;
		}
		else if (kipper<0) {
			answer = Math.max(-sliceSize, kipper);
		}
		else {
			answer = Math.min(sliceSize, kipper);
		}
		kipper -= answer;
		return answer;
	}
	
	boolean more() {
		return kipper!=0;
	}
}
