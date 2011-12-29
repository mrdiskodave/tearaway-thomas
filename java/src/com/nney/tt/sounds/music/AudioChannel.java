package com.nney.tt.sounds.music;

public class AudioChannel {
	/**
	 * Used to give us more precision when dealing with Amiga audio periods.
	 */
	private static final int PERIOD_BOOSTER = 1024;

	/**
	 * The bus rate of the Amiga (which was part of the basis on which it's
	 * audio periods were calculated).
	 */
	private static final double AMIGA_BUS_RATE = 2.79365e-7;

	/**
	 * How much of the output comes from the current sample and how much from
	 * the last? <code>1.0f</code> would disable the low-pass filter entirely.
	 * If you change {@link MusicPlayer#FREQUENCY} you'll need to tweak this to
	 * taste because I don't know how to calculate it.
	 */
	private static final double LOWPASS_FILTER_FACTOR = 0.5f;

	/**
	 * So we can read Amiga samples at the right speed.
	 */
	private static final int MAGIC_RATIO = (int) (((1.0 / MusicPlayer.FREQUENCY) / AMIGA_BUS_RATE) * PERIOD_BOOSTER);

	/**
	 * Maximum volume. I've raised it to 256 when the Amiga used 64. This is
	 * easy as my play routine used 256 internally.
	 */
	public static final int MAXIMUM_VOLUME = 256;

	/**
	 * What wave are we playing?
	 */
	public byte[] wave;

	/**
	 * Does the sample repeat at the end?
	 */
	public boolean repeat;

	/**
	 * What is our period currently set to? This is the same value you'd set
	 * into the Amiga hardware.
	 */
	public int period;

	/**
	 * What is our volume currently set to? Zero to {@link #MAXIMUM_VOLUME}.
	 */
	public int volume;

	/**
	 * What is our byte index within the wave?
	 */
	private int pos;

	/**
	 * A fractional accumulator so we know when to dole out fresh
	 * {@link #sample()}s.
	 */
	private int acc;

	/**
	 * Used by the low pass filter.
	 */
	private double lastResult;

	void wave(byte[] w, boolean r) {
		wave = w;
		repeat = r;

		pos = 0;
		acc = 0;
	}

	int sample() {
		if (wave == null) return 0;

		int rawSample = wave[pos];

		//
		// volume
		//

		int volumeAdjustedSample = (rawSample * volume) / MAXIMUM_VOLUME;

		//
		// low pass filter
		//
		double currentResult = volumeAdjustedSample;

		// lastResult = FILTER_FACTOR * currentResult + (1 - FILTER_FACTOR) *
		// lastResult;
		// i.e.
		lastResult = lastResult + LOWPASS_FILTER_FACTOR * (currentResult - lastResult);

		//
		// advance our position for next time
		//
		if (acc <= 0) {
			acc += period;
			pos++;
			if (pos == wave.length) {
				if (repeat) {
					pos = 0;
				}
				else {
					wave = null;
				}
			}
		}
		acc -= MAGIC_RATIO;

		return (int) lastResult;
	}

	void period(int p) {
		period = p * PERIOD_BOOSTER;
		assert period > MAGIC_RATIO;
	}

	void volume(int v) {
		assert v <= MAXIMUM_VOLUME;
		volume = v;
	}
}
