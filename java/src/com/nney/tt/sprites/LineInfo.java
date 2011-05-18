package com.nney.tt.sprites;

import com.nney.tt.gfx.SimpleImage;

public final class LineInfo {

	/**
	 * Generate line info for the given {@link SimpleImage}.
	 * 
	 * @param si
	 *            The image.
	 * @return The line info.
	 */
	static byte[] generate(SimpleImage si) {
		byte[] li = new byte[si.height() * 2];
		for (int y = 0; y < si.height(); y++) {
			int right = si.width() - 1;
			while (right >= 0 && si.get(right, y) == 0) {
				right--;
			}
			if (right < 0) {
				// empty line
				li[2 * y] = (byte) 0;
				li[2 * y + 1] = (byte) 0;
			}
			else {
				// non-empty line
				int left = 0;
				while (si.get(left, y) == 0) {
					left++;
				}
				int width = right - left + 1;
				li[2 * y] = (byte) left;
				li[2 * y + 1] = (byte) width;
			}
		}
		return li;
	}

	/**
	 * Collide two {@link SimpleImage}s by their line info.
	 * 
	 * Call this once you've established that the images bounding boxes overlap.
	 * 
	 * @param a
	 *            Line info for image 'a' which must be the higher of the two
	 *            images.
	 * @param b
	 *            Line info for image 'b' which must be the lower of the two
	 *            images.
	 * @param ay
	 *            The row number (i.e. y position) within image 'a' where 'b'
	 *            begins.
	 * @param axmbx
	 *            The x screen position of image 'a' minus the x screen position
	 *            of image 'b'.
	 * @return Is there a collision? <code>true</code> meaning "there is" or
	 *         <code>false</code> meaning "there is not".
	 */
	public static boolean collide(byte[] a, byte[] b, int ay, int axmbx) {
		ay *= 2;
		int by = 0;
		do {
			int dx = axmbx + a[ay] - b[by];
			if (dx < b[by + 1] && dx > (-a[ay + 1])) return true;
			by += 2;
			ay += 2;
		} while (ay < a.length && by < b.length);
		return false;
	}
}
