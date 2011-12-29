package com.nney.tt.osd;

public class Justify {
	private static final int LOW = 1;
	private static final int HIGH = 2;

	public static final int NORTH = LOW << 4;
	public static final int SOUTH = HIGH << 4;
	public static final int WEST = LOW;
	public static final int EAST = HIGH;
	public static final int NORTHWEST = NORTH | WEST;
	public static final int NORTHEAST = NORTH | EAST;
	public static final int SOUTHWEST = SOUTH | WEST;
	public static final int SOUTHEAST = SOUTH | EAST;
	public static final int CENTRED = 0;

	public static int x(int justify, int content, int cell) {
		return j(justify & 0xf, content, cell);
	}

	public static int y(int justify, int content, int cell) {
		return j(justify >> 4, content, cell);
	}

	private static int j(int justify, int content, int cell) {
		if (justify == LOW) return 0;
		if (justify == HIGH) return cell - content;
		return (cell - content) / 2;
	}
}
