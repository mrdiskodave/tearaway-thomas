package com.nney.tt.j2d;

/**
 * Paces the game at a fixed frame rate (the original ran at 50Hz PAL).
 *
 * When running in real time it also reports, every few seconds, the frame rate
 * actually achieved and how long each frame's work took (from waking up to
 * asking for the next frame), so slowdowns can be told apart: work that takes
 * too long, or sleeps that overrun.
 */
public class FrameClock {
	private static final long REPORT_NANOS = 4000000000L;

	private final int fps;
	private final long frameNanos;
	private final boolean realTime;
	private long next;

	// for the report
	private long reportStart;
	private long woke;
	private int frames;
	private long busyTotal;
	private long busyWorst;
	private int late;
	private int resyncs;

	/**
	 * @param fps
	 *            Frames per second.
	 * @param realTime
	 *            <code>false</code> to run as fast as possible (used for
	 *            headless testing).
	 */
	public FrameClock(int fps, boolean realTime) {
		this.fps = fps;
		this.frameNanos = 1000000000L / fps;
		this.realTime = realTime;
	}

	public void waitForNextFrame() {
		if (!realTime) return;
		long now = System.nanoTime();
		measure(now);
		if (next == 0 || now - next > frameNanos * 5) {
			// first frame, or we fell badly behind (e.g. a breakpoint): resync
			if (next != 0) resyncs++;
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
		else {
			late++;
		}
		woke = System.nanoTime();
	}

	private void measure(long now) {
		if (reportStart == 0) {
			reportStart = now;
			return;
		}
		long busy = now - woke;
		busyTotal += busy;
		busyWorst = Math.max(busyWorst, busy);
		frames++;

		long elapsed = now - reportStart;
		if (elapsed >= REPORT_NANOS) {
			System.out.printf("fps %.1f (target %d) | work per frame %.1fms average, %.1fms worst | %d late%s%n",
					frames * 1e9 / elapsed, fps, busyTotal / 1e6 / frames, busyWorst / 1e6, late,
					resyncs > 0 ? ", " + resyncs + " resync" + (resyncs > 1 ? "s" : "") : "");
			reportStart = now;
			frames = 0;
			busyTotal = 0;
			busyWorst = 0;
			late = 0;
			resyncs = 0;
		}
	}
}
