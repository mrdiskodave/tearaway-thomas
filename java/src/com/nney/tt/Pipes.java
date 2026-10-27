package com.nney.tt;

import com.nney.tt.geom.Coord;

/**
 * Futureland's pipes: the data from s195 (pipe_table, pipevecs, pipequittab).
 * 
 * Directions are 0 north, 1 east, 2 south, 3 west. Pipe blocks are map blocks
 * 160 to 279. For each, the table gives the direction you leave it in for each
 * direction you arrive in; 4 means "this isn't pipe", and you're blasted out.
 */
public final class Pipes {
	private Pipes() {
	}

	public static final int NORTH = 0;
	public static final int EAST = 1;
	public static final int SOUTH = 2;
	public static final int WEST = 3;
	static final int OUT = 4;

	static final int FIRST_BLOCK = 160;

	/** pipe_table: [block - 160][direction in] = direction out. */
	static final int[][] TABLE = {
			{1,1,2,2}, {1,1,2,3}, {3,1,2,3}, {3,2,2,3}, {0,1,2,0}, {0,1,2,3}, {0,1,2,3}, {0,0,2,3}, {0,1,2,3}, {0,1,2,3}, // blocks 160-169
			{0,1,2,3}, {0,1,2,3}, {4,1,4,3}, {4,1,4,3}, {1,1,2,2}, {1,1,2,3}, {3,1,2,3}, {3,2,2,3}, {4,1,4,3}, {4,1,4,3}, // blocks 170-179
			{0,1,2,2}, {0,1,2,3}, {0,1,2,3}, {0,2,2,3}, {0,1,1,0}, {0,1,1,3}, {0,1,3,3}, {0,0,3,3}, {0,1,2,3}, {0,1,2,3}, // blocks 180-189
			{0,1,2,3}, {0,1,2,3}, {4,1,4,3}, {4,1,4,3}, {0,1,2,2}, {0,1,2,3}, {0,1,2,3}, {0,2,2,3}, {4,1,4,3}, {4,1,4,3}, // blocks 190-199
			{4,1,4,3}, {4,1,4,3}, {4,1,4,3}, {0,4,2,4}, {0,4,2,4}, {0,4,2,4}, {0,4,2,4}, {0,4,2,4}, {0,4,2,4}, {4,1,4,3}, // blocks 200-209
			{4,1,4,3}, {4,1,4,3}, {4,1,4,3}, {4,1,4,3}, {0,1,2,0}, {0,1,2,3}, {0,1,2,3}, {0,0,2,3}, {0,4,2,4}, {0,4,2,4}, // blocks 210-219
			{4,1,4,3}, {4,1,4,3}, {4,1,4,3}, {0,4,2,4}, {0,4,2,4}, {4,4,4,4}, {4,4,4,4}, {0,4,2,4}, {0,4,2,4}, {4,1,4,3}, // blocks 220-229
			{4,1,4,3}, {4,1,4,3}, {4,1,4,3}, {4,1,4,3}, {0,1,1,0}, {0,1,1,3}, {0,1,3,3}, {0,0,3,3}, {0,4,2,4}, {0,4,2,4}, // blocks 230-239
			{1,1,2,2}, {1,1,2,3}, {3,1,2,3}, {3,2,2,3}, {0,1,2,0}, {0,1,2,3}, {0,1,2,3}, {0,0,2,3}, {0,1,2,3}, {0,1,2,3}, // blocks 240-249
			{0,1,2,3}, {0,1,2,3}, {0,4,2,4}, {0,4,2,4}, {0,1,2,3}, {0,1,2,3}, {0,1,2,3}, {0,1,2,3}, {0,1,2,3}, {0,1,2,3}, // blocks 250-259
			{0,1,2,2}, {0,1,2,3}, {0,1,2,3}, {0,2,2,3}, {0,1,1,0}, {0,1,1,3}, {0,1,3,3}, {0,0,3,3}, {0,1,2,3}, {0,1,2,3}, // blocks 260-269
			{0,1,2,3}, {0,1,2,3}, {0,4,2,4}, {0,4,2,4}, {0,1,2,3}, {0,1,2,3}, {0,1,2,3}, {0,1,2,3}, {0,1,2,3}, {0,1,2,3}, // blocks 270-279
	};

	/** pipevecs: one pixel in each direction. */
	static final Coord[] STEP = { new Coord(0, -1), new Coord(1, 0), new Coord(0, 1), new Coord(-1, 0) };

	/** pipequittab: where you pop out, relative to where the pipe ended. */
	static final Coord[] EXIT_OFFSET = { new Coord(0, 0), new Coord(23, 12), new Coord(0, 23), new Coord(-23, 12) };

	/** pipequittab: the direction you're blasted in when you come out. */
	static final Coord[] BLAST = { new Coord(0, 0), new Coord(1, 0), new Coord(0, 1), new Coord(-1, 0) };

	/** What happens to someone going this way through this block? */
	static int turn(int block, int direction) {
		int i = block - FIRST_BLOCK;
		if (i < 0 || i >= TABLE.length) return OUT;
		return TABLE[i][direction];
	}
}
