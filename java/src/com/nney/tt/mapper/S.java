package com.nney.tt.mapper;

class S {
	public static final int FIRST = 0;
	public static final int SECOND = 1;

	final static public int WIDTH = 20;
	final static public Range rEmpty = new Range(0, 1);
	final static public Range rWalls = new Range(1, WIDTH);
	final static public Range rSpaces = new Range(WIDTH, WIDTH * 2);
	final static public Range rSpecial = new Range(WIDTH * 2, WIDTH * 3);

	final static public int NONE = -1;
	final static public int HIDDEN = 0;

	private int wall = NONE;
	private int space = NONE;
	private int special = NONE;

	private int col = 0;
	private int which = 0; // which
	private boolean pips = false;
	private int shadow = 0;

	int wall() {
		return wall;
	}
	
	int space() {
		return space;
	}
	
	int special() {
		return special;
	}
	
	int col() {
		return col;
	}
	
	int which() {
		return which;
	}
	
	boolean pips() {
		return pips;
	}
	
	int shadow() {
		return shadow;
	}
	
	static S fromBlock(int b) {
		if (b<0) return null;
		S s = new S();
		if (rEmpty.in(b)) return s;
		int x;
		x = rWalls.much(b);
		if (x>=0) {
			s.wall(x);
			return s;
		}
		else {
			x = rSpaces.much(b);
			if (x>=0) {
				s.space(x);
				return s;
			}
			else {
				x = rSpecial.much(b);
				if (x>=0) {
					s.special(x);
					return s;
				}
			}
		}
		return null;
	}
	
	@Override
	public String toString() {
		if (wall >= 0) {
			return String.format("wall%s col%s", wall, col);
		}
		// assert style >= 0;
		return String.format("wall%s space%s special%s col%s which%s pips%s shaddow%s", wall, space, special, col,
				which, pips, shadow);
	}

	int flattern() {
		int f = 0;
		f = merge(f, wall + 1);
		f = merge(f, (space + 1)*2+which);
		f = merge(f, special + 1);
		f = merge(f, col);
		f = merge(f, pips ? 1 : 0);
		f = merge(f, shadow);
		return f;
	}

	private static int merge(int x, int i) {
		int b = 4;
		int m = (1 << b) - 1;
		assert 0 <= i && i <= m;
		x <<= b;
		x |= i & m;
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

	public S space(int x) {
		space = x;
		return this;
	}

	public S which(int x) {
		which = x;
		return this;
	}

	public S wall(int x) {
		wall = x;
		return this;
	}

	public S special(int x) {
		special = x;
		return this;
	}

	public S copy() {
		S a = new S();
		a.wall = wall;
		a.space = space;
		a.special = special;

		a.col = col;
		a.which = which;
		a.pips = pips;
		a.shadow = shadow;
		return a;
	}
}