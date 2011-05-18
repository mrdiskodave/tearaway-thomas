package com.nney.tt.mapper;

import java.security.InvalidParameterException;

public class Cycle {
	private final int top;
	private int x;
	private final int scale;
	private final int rate;
	private int length;

	Cycle(int top, int scale, int rate) {
		if (top <= 0 || scale <= 0 || rate <= 0) {
			throw new InvalidParameterException();
		}
		this.top = top;
		this.scale = scale;
		this.rate = rate;
		this.length = top * 2;
	}

	Cycle(int top) {
		this(top, 1, 1);
	}

	int next() {
		int answer = current();
		advance();
		return answer;
	}

	int current() {
		int answer = x / scale;
		if (answer > top) {
			answer = 2 * top - answer;
		}
		return answer;
	}

	void advance() {
		x += rate;
		if (x >= length * scale) {
			x -= length * scale;
		}

	}
}
