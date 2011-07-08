package sandbox.lwjgl.demos.openal;

public class AudioChan {
	public byte[] sample;
	public boolean repeat;
	public int freq;
	public int vol;

	void sample(byte[] s, boolean r) {
		sample = s;
		repeat = r;
	}
	
	void freq(int f) {
		freq = f;
	}
	
	void vol(int v) {
		vol = v;
	}
}
