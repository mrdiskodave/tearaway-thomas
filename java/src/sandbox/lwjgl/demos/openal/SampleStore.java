package sandbox.lwjgl.demos.openal;

import java.util.Arrays;

public class SampleStore {
	private short[] data;
	private int pos;

	/**
	 * Create it to hold a certain number of samples.
	 * 
	 * @param capacity
	 */
	public SampleStore(int capacity) {
		data = new short[capacity * 2];
		pos = 0;
	}

	/**
	 * Add a sample advancing the position.
	 * 
	 * @param l
	 *            Left channel.
	 * @param r
	 *            Right Channel.
	 */
	public void add(short l, short r) {
		data[pos++] = l;
		data[pos++] = r;
	}

	/**
	 * Collect all the submitted samples up until the position.
	 * 
	 * @return An array of the form
	 *         <code>{ left, right, left, right, ... }</code>.
	 */
	public short[] collect() {
		return pos == data.length ? data : Arrays.copyOf(data, pos);
	}

	/**
	 * @return Where is the position?
	 */
	public int pos() {
		return pos / 2;
	}

	/**
	 * Trim silence from the end of this object making it smaller. Changes the
	 * position to reflect this.
	 */
	public void rewindOverSilence() {
		int l = pos;
		while (l != 0 && (data[l - 2] | data[l - 1]) == 0) {
			l -= 2;
		}
		pos = l;
	}

	public void dumpRange() {
		int vMin = Integer.MAX_VALUE;
		int vMax = Integer.MIN_VALUE;
		for (int x = 0; x < pos; x++) {
			short s = data[x];
			vMin = Math.min(s, vMin);
			vMax = Math.max(s, vMax);
		}
		System.out.println(pos + " samples between " + vMin + " and " + vMax);
	}

}
