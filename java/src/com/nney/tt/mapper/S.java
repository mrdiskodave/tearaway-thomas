package com.nney.tt.mapper;

class S {
	int wall = -1;

	int col = 0;

	int style = -1;
	int which = -1;
	boolean pips = false;
	int shadow = 0;
	boolean magic = false;

	@Override
	public String toString() {
		if (wall >= 0) {
			return String.format("wall%s col%s", wall, col);
		}
		// assert style >= 0;
		return String.format("style%s which%s pips%s (col%s) shaddow%s magic%s", style, which, pips, col, shadow,
				magic);
	}

	int flattern() {
		return compose(col, pips ? 1 : 0, shadow, style, wall, which, magic ? 1 : 0);
	}
	
	static private int compose(int... d) {
		int x = 0;
		for (int i : d) {
			assert i >= -1 && i <= 14;
			x <<= 4;
			x |= i & 15;
		}
		return x;
	}

	S col(int x) {
		col = x;
		return this;
	}

	S pips(boolean x) {
		pips = x;
		return this;
	}

	S shadow(int x) {
		shadow = x;
		return this;
	}

	public S style(int x, int y) {
		style = x;
		which = y;
		return this;
	}

	public S wall(int x) {
		wall = x;
		return this;
	}

	public S magic(boolean b) {
		magic = b;
		return this;
	}

	public S copy() {
		S a = new S();
		a.wall = wall;
		a.col = col;
		a.style = style;
		a.which = which;
		a.pips = pips;
		a.shadow = shadow;
		a.magic = magic;
		return a;
	}
}