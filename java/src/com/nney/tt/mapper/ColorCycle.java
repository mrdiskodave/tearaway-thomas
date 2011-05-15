package com.nney.tt.mapper;

public class ColorCycle {
	private static final int MAGIC_COMPONENT1 = 0x55;
	private static final int MAGIC_COMPONENT2 = 0xaa;
	private Cycle c = new Cycle(15, 100, 80);

	public int process(int color) {
		int component = getComponent();
		int answer = substituteComponent(color, component);
		return answer;
	}

	public void advance() {
		c.next();
	}

	private int substituteComponent(int color, int component) {
		int answer = 0;
		for (int p = 0; p < 4; p++) {
			int shift = p * 8;
			int v = (color >> shift) & 0xff;
			if (v == MAGIC_COMPONENT1) {
				v = component;
			} else if (v == MAGIC_COMPONENT2) {
				v = ~component & 0xff;
			}
			answer |= v << shift;
		}
		return answer;
	}

	private int getComponent() {
		int x = c.current();
		assert x>=0 && x<16;
		x |= (x << 4);
		return x;
	}

}
