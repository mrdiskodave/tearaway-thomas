package com.nney.tt.j2d;

/**
 * Paces the game at a fixed frame rate (the original ran at 50Hz PAL).
 */
public class FrameClock {
	private final long frameNanos;
	private final boolean realTime;
	private long next;

	/**
	 * @param fps
	 *            Frames per second.
	 * @param realTime
	 *            <code>false</code> to run as fast as possible (used for
	 *            headless testing).
	 */
	public FrameClock(int fps, boolean realTime) {
		this.frameNanos = 1000000000L / fps;
		this.realTime = realTime;
	}

	public void waitForNextFrame() {
		if (!realTime) return;
		long now = System.nanoTime();
		if (next == 0 || now - next > frameNanos * 5) {
			// first frame, or we fell badly behind (e.g. a breakpoint): resync
			next = now;
		}
		next += frameNanos;
		long sleep = next - System.nanoTime();
		if (sleep > 0) {
			try {
				Thread.sleep(sleep / 1000000L, (int) (sleep % 1000000L));
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}
}
