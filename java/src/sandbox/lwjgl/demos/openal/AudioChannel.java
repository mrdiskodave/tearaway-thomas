package sandbox.lwjgl.demos.openal;

public class AudioChannel {
	/**
	 * ((1.0/44100)/amigaBusRate)*256 = 20779.226682410175
	 * 
	 * amigaBusRate = 2.79365e-7
	 */
	private static final int MAGIC_RATIO = 20779;
	
	/**
	 * What wave are we playing?
	 */
	public byte[] wave;
	
	/**
	 * Does the sample repeat at the end?
	 */
	public boolean repeat;
	
	/**
	 * What is our period currently set to?
	 * This is the same value you'd set into the Amiga hardware.
	 */
	public int period;
	
	/**
	 * What is our volume currently set to?
	 * This is the same value you'd set into the Amiga hardware.
	 */
	public int volume;

	/**
	 * What is our byte index within the wave?
	 */
	private int pos;
	
	/**
	 * A fractional accumulator so we know when to dole out fresh {@link #sample()}s.
	 */
	private int acc;

	
	void wave(byte[] w, boolean r) {
		wave = w;
		repeat = r;

		pos = 0;
		acc = 0;
	}
	
	int sample() {
		if (wave==null) return 0;

		int p = pos;
		
		if (acc<=0) {
			acc += period;
			pos ++;
			if (pos==wave.length) {
				if (repeat) {
					pos = 0;
				}
				else {
					wave = null;
					return 0;
				}
			}
		}
		acc -= MAGIC_RATIO;

		return (wave[p]*volume)/0x40;
	}
	
	void period(int p) {
		period = p*256;
		assert period<MAGIC_RATIO;
	}
	
	void volume(int v) {
		volume = v;
	}
}
