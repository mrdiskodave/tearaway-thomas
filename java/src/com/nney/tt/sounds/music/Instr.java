package com.nney.tt.sounds.music;


public class Instr {
	private static final int Isamplen = 0;
	private static final int Iname = 2;
	private static final int Iloop = 10;
	private static final int Itone = 42;
	private static final int Iasdr = 58;
	
	/**
	 * Always 2 if it is anything. We should just read the tone data faster
	 * or hardwire the 2. (currently doing neither!)
	 */
	private static final int Itone_speed = 66;
	
	private static final int Itone_pause = 67;
	private static final int Itone_mulu = 68;
	private static final int Isqr_rate = 69;
	private static final int Isqr_begin = 70;
	private static final int Isqr_end = 71;
	private static final int Iloop_size = 72;
	private static final int Itone_size = 73;
	
	private int sample;

	public byte[] loop;
	public byte[] tone;
	public byte[] asdr;
	public int tonePause;
	public int sqrRate;
	public int sqrBegin;
	public int sqrEnd;

	
	public Instr(DataSrc dataSrc) {
		sample = dataSrc.unsignedWord(Isamplen);
		if (sample == 0) {
			loop = dataSrc.rawData(Iloop, dataSrc.unsignedByte(Iloop_size)*2);
			tone = dataSrc.rawData(Itone, dataSrc.unsignedByte(Itone_size)*2);
			asdr = dataSrc.rawData(Iasdr, 8);

			int toneMulu = dataSrc.unsignedByte(Itone_mulu);
			for (int x=0; x<tone.length; x++) {
				tone[x] *= toneMulu;
			}
			tonePause = dataSrc.unsignedByte(Itone_pause);
			
			sqrRate = dataSrc.unsignedByte(Isqr_rate);
			sqrBegin = dataSrc.unsignedByte(Isqr_begin);
			sqrEnd = dataSrc.unsignedByte(Isqr_end);
			
			if (sqrBegin>=loop.length) {
				sqrRate = 0;
			}
		}
	}

	void dump() {
		if (sample==0) {
			String morph = "";
			if (sqrRate!=0) {
				morph = String.format(",b%s,e%s,r%s", sqrBegin, sqrEnd, sqrRate);
			}
			System.out.println(String.format("loop:%s[%s]%s", DebugTools.showBin(loop), loop.length, morph));
			System.out.println(String.format("tone:%s[%s],pause=%s", DebugTools.showBin(tone), tone.length, tonePause));
			System.out.println(String.format("asdr:%s", DebugTools.showBin(asdr)));
			System.out.println(".");
		}
		else {
			System.out.println("Sample:"+sample);
		}
	}
	
	boolean isSynthasized() {
		return sample==0;
	}

	public void bind(byte[][] waves) {
		if (sample!=0) {
			System.out.println("SAMPLE:"+sample);
			loop = waves[sample-1];
		}
	}
}
