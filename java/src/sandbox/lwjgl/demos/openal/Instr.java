package sandbox.lwjgl.demos.openal;

public class Instr {
	static final int Isamplen = 0;
	static final int Iname = 2;
	static final int Iloop = 10;
	static final int Itone = 42;
	static final int Iasdr = 58;
	static final int Itone_speed = 66;
	static final int Itone_pause = 67;
	static final int Itone_mulu = 68;
	static final int Isqr_rate = 69;
	static final int Isqr_begin = 70;
	static final int Isqr_end = 71;
	static final int Iloop_size = 72;
	static final int Itone_size = 73;
	
	public int sample;

	public byte[] loop;
	public byte[] tone;
	public byte[] asdr;
	public int tonePause;
	public int toneMulu;
	public int sqrRate;
	public int sqrBegin;
	public int sqrEnd;

	String showBin(byte[] b) {
		StringBuffer sb = new StringBuffer();
		for (int x=0; x<b.length; x++) {
			sb.append(String.format("%02x", b[x]));
		}
		return sb.toString();
	}
	
	public Instr(DataSrc dataSrc) {
		sample = dataSrc.uw(Isamplen);
		if (sample == 0) {
			loop = dataSrc.xx(Iloop, dataSrc.ub(Iloop_size));
			tone = dataSrc.xx(Itone, dataSrc.ub(Itone_size));
			asdr = dataSrc.xx(Iasdr, 8);

			int toneMulu = dataSrc.ub(Itone_mulu);
			for (int x=0; x<tone.length; x++) {
				tone[x] *= toneMulu;
			}
			tonePause = dataSrc.ub(Itone_pause);
			
			sqrRate = dataSrc.ub(Isqr_rate);
			sqrBegin = dataSrc.ub(Isqr_begin);
			sqrEnd = dataSrc.ub(Isqr_end);
			
			if (sqrBegin>=loop.length) {
				sqrRate = 0;
			}
			String morph = "";
			if (sqrRate!=0) {
				morph = String.format(",b%s,e%s,r%s", sqrBegin, sqrEnd, sqrRate);
			}
			System.out.println(String.format("loop:%s[%s]%s", showBin(loop), loop.length, morph));
			System.out.println(String.format("tone:%s,pause=%s", showBin(tone), tonePause));
			System.out.println(String.format("asdr:%s", showBin(asdr)));
			System.out.println(".");
		}
		else {
			System.out.println("Sample:"+sample);
		}
	}
}
