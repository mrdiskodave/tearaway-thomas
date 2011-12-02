package com.nney.tt.toygen;

import com.nney.tt.BlockAccess;
import com.nney.tt.geom.Coord;

/**
 * When computing a block {@link ToyGenerator#run()} needs to read the
 * surrounding original blocks as input. If do we do this entirely in-place
 * then, as we compute every block, we'll end up reading our output back in as
 * input in a loop! One way around would be a full double-buffer but we only
 * really need a couple of rows lee-way. That is what this class provides.
 */
class DelayedBlockWriter {
	private short[][] queue;
	private final BlockAccess ba;
	private int y;

	public DelayedBlockWriter(BlockAccess ba, int delay) {
		this.queue = new short[delay][];
		this.ba = ba;
	}

	void put(short[] row) {
		short[] leaving = queue[0];
		if (leaving != null) {
			for (int x = 0; x < ba.width(); x++) {
				ba.set(new Coord(x, y), leaving[x]);
			}
			y++;
		}
		System.arraycopy(queue, 1, queue, 0, queue.length - 1);
		queue[queue.length - 1] = row;
	}

	void flush() {
		while (y < ba.height()) {
			put(null);
		}
	}
}