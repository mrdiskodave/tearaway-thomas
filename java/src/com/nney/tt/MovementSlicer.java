package com.nney.tt;

public class MovementSlicer {
	private int kipper;

	public MovementSlicer(int distance) {
		this.kipper = distance;
	}
	
	public int next(int slice) {
		if (slice<=0) {
			throw new IllegalArgumentException();
		}
		int answer;
		if (kipper==0) {
			answer = 0;
		}
		else if (kipper<0) {
			answer = Math.max(-slice, kipper);
		}
		else {
			answer = Math.min(slice, kipper);
		}
		kipper -= answer;
		return answer;
	}
	
	public boolean more() {
		return kipper!=0;
	}
}
