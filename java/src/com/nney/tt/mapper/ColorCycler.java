package com.nney.tt.mapper;

public class ColorCycler {
	private Cycle c = new Cycle(15, 100, 80);

	public int process(int color) {
		return color | getOrIn();
	}

	public void advance() {
		c.next();
	}

	private int getOrIn() {
		int v = c.current();
		int answer = 0;
		for (int x=0; x<6; x++) {
			answer |= v<<(x*4);
		}
		return answer;
	}

}
