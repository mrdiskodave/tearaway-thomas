package com.nney.tt.j2d;

import com.nney.tt.gfx.FrameRateReport;

/**
 * Paces the game at a fixed frame rate (the original ran at 50Hz PAL).
 *
 * When running in real time it also reports the frame rate achieved (see
 * {@link FrameRateReport}). The work per frame is from waking up to asking for
 * the next frame, so slowdowns can be told apart: work that takes too long, or
 * sleeps that overrun.
 */
public class FrameClock {
	private final long frameNanos;
	private final boolean realTime;
	private final FrameRateReport report;
	private long next;
	private long woke;

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
		this.report = new FrameRateReport("Java2D", fps, true);
	}

	public void waitForNextFrame() {
		if (!realTime) return;
		long now = System.nanoTime();
		long work = now - woke;
		boolean resynced = false;
		if (next == 0 || now - next > frameNanos * 5) {
			// first frame, or we fell badly behind (e.g. a breakpoint): resync
			resynced = next != 0;
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
		report.frame(now, work, sleep <= 0, resynced);
		woke = System.nanoTime();
	}
}
