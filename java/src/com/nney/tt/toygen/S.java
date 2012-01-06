package com.nney.tt.toygen;

/**
 * All the different things that a Toyland block can be -- represented in a
 * structured (machine read/writable) fashion.
 */
class S {
	public static final int SPACE_COUNT = 5;
	public static final int WALL_COUNT = 6;
	public static final int SPECIAL_COUNT = 1;

	final static public int WIDTH = 20;
	final static public Range rSpaces = new Range(0, SPACE_COUNT);
	final static public Range rWalls = new Range(WIDTH, WALL_COUNT);
	final static public Range rSpecial = new Range(WIDTH * 2, SPECIAL_COUNT);

	public static final int SHADOW_COUNT = 7;

	final static public int NONE = -1;
	final static public int SPECIAL_MAGIC = 0;

	private int wall = NONE;
	private int space = NONE;
	private int special = NONE;

	private int col = 0;
	private boolean which;
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

	public boolean isWall() {
		return wall >= 0;
	}

	public boolean isSpace() {
		return space >= 0;
	}

	public boolean isSpecial() {
		return special >= 0;
	}

	boolean isWhich() {
		return which;
	}

	boolean isPips() {
		return pips;
	}

	int shadow() {
		return shadow;
	}

	static S fromBlock(int b) {
		S s = new S();
		if (b < 0) return s;
		int x;
		x = rWalls.much(b);
		if (x >= 0) {
			s.wall(1); // anything will do
			s.col(x);
			return s;
		}
		else {
			x = rSpaces.much(b);
			if (x >= 0) {
				s.space(x);
				return s;
			}
			else {
				x = rSpecial.much(b);
				if (x >= 0) {
					s.special(x);
					return s;
				}
			}
		}
		return null;
	}

	public void checkInvariants() {
		if (isWall()) {
			assert !isSpace();
			assert !isSpecial();
			assert !which;
			assert !isPips();
			assert shadow == 0;
		}
		else {
			if (!isPips()) {
				assert col == 0;
			}
		}
	}

	@Override
	public String toString() {
		int f = flattern();
		if (isWall()) {
			return String.format("%08x wall%s col%s", f, wall, col);
		}
		return String.format("%08x space%s special%s col%s which%s pips%s shaddow%s", f, space, special, col, which,
				pips, shadow);
	}

	int flattern() {
		checkInvariants();
		int f = 0;
		f = merge(f, wall + 1);
		f = merge(f, (space + 1) * 2 + (which ? 1 : 0));
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

	public S which(boolean x) {
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

	public boolean isWallOfSameCol(S o) {
		return o.isWall() && col() == o.col();
	}

}