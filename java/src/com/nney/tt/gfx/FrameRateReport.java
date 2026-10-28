package com.nney.tt.gfx;

/**
 * Prints, every few seconds, the frame rate actually achieved and how long each
 * frame's work took. Used by both front ends so they can be compared.
 */
public class FrameRateReport {
	private static final long REPORT_NANOS = 4000000000L;

	private final String name;
	private final int target;
	private final boolean countsLate;

	private long reportStart;
	private int frames;
	private long workTotal;
	private long workWorst;
	private int late;
	private int resyncs;

	/**
	 * @param name
	 *            Which front end, shown at the start of each line.
	 * @param target
	 *            The frame rate we're aiming for.
	 * @param countsLate
	 *            Whether the caller reports late frames and resyncs.
	 */
	public FrameRateReport(String name, int target, boolean countsLate) {
		this.name = name;
		this.target = target;
		this.countsLate = countsLate;
	}

	/**
	 * Call once a frame.
	 * 
	 * @param workNanos
	 *            How long the last frame's work took.
	 */
	public void frame(long now, long workNanos, boolean wasLate, boolean resynced) {
		if (reportStart == 0) {
			reportStart = now;
			return;
		}
		frames++;
		workTotal += workNanos;
		workWorst = Math.max(workWorst, workNanos);
		if (wasLate) late++;
		if (resynced) resyncs++;

		long elapsed = now - reportStart;
		if (elapsed >= REPORT_NANOS) {
			StringBuilder sb = new StringBuilder();
			sb.append(String.format("%s fps %.1f (target %d) | work per frame %.1fms average, %.1fms worst", name,
					frames * 1e9 / elapsed, target, workTotal / 1e6 / frames, workWorst / 1e6));
			if (countsLate) {
				sb.append(" | ").append(late).append(" late");
				if (resyncs > 0) sb.append(", ").append(resyncs).append(resyncs > 1 ? " resyncs" : " resync");
			}
			System.out.println(sb);
			reportStart = now;
			frames = 0;
			workTotal = 0;
			workWorst = 0;
			late = 0;
			resyncs = 0;
		}
	}
}
