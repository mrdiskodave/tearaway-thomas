package com.nney.tt.input;

/**
 * Plays back a joystick recording from the original game's demo files: one
 * byte per frame in the Amiga's own bit layout (which our {@link Joystick}
 * constants share), ended by a negative byte.
 * 
 * Each {@link #get()} moves on one frame.
 */
public class RecordedJoystick implements Joystick {
	private final byte[] data;
	private final int length;
	private final boolean loop;
	private int pos;
	private boolean finished;

	/**
	 * @param data
	 *            The recording.
	 * @param maxFrames
	 *            Use at most this many frames of it (-1 for all). The original
	 *            trimmed the intro recording this way.
	 * @param loop
	 *            Start again from the beginning when we reach the end
	 *            (otherwise just let go of the stick).
	 */
	public RecordedJoystick(byte[] data, int maxFrames, boolean loop) {
		this.data = data;
		int n = 0;
		while (n < data.length && data[n] >= 0) {
			n++;
		}
		if (maxFrames >= 0) n = Math.min(n, maxFrames);
		this.length = n;
		this.loop = loop;
	}

	@Override
	public int get() {
		if (length == 0) return 0;
		if (pos >= length) {
			if (!loop) {
				finished = true;
				return 0;
			}
			pos = 0;
		}
		return data[pos++] & 0x1f;
	}

	/** Have we run off the end (only if not looping)? */
	public boolean isFinished() {
		return finished;
	}

	public int frames() {
		return length;
	}
}
