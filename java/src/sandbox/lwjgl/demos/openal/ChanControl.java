package sandbox.lwjgl.demos.openal;

import com.nney.utils.Math2;

public class ChanControl {

	private final AudioChan h;

	ChanControl(AudioChan h) {
		this.h = h;
	}

	static int NOTE_FREQ[] = { 65406, // 0
			69295, // 1
			73416, // 2
			77781, // 3
			82406, // 4
			87307, // 5
			92498, // 6
			97998, // 7
			103826, // 8
			110000, // 9
			116540, // 10
			123470, // 11
			130812, // 12
			138591, // 13
			146832, // 14
			155563, // 15
			164813, // 16
			174614, // 17
			184997, // 18
			195997, // 19
			207652, // 20
			220000, // 21
			233081, // 22
			246941, // 23
			261625, // 24
			277182, // 25
			293664, // 26
			311126, // 27
			329627, // 28
			349228, // 29
			369994, // 30
			391995, // 31
			415304, // 32
			440000, // 33
			466163, // 34
			493883, // 35
			523251, // 36
			554365, // 37
			587329, // 38
			622253, // 39
			659255, // 40
			698456, // 41
			739988, // 42
			783990, // 43
			830609, // 44
			880000, // 45
			932327, // 46
			987766, // 47
			1046502, // 48
			1108730, // 49
			1174659, // 50
			1244507, // 51
			1318510, // 52
			1396912, // 53
			1479977, // 54
			1567981, // 55
			1661218, // 56
			1760000, // 57
			1864655, // 58
			1975533, // 59
			2093004, // 60
			2217461, // 61
			2349318, // 62
			2489015, // 63
			2637020, // 64
			2793825, // 65
			2959955, // 66
			3135963, // 67
			3322437, // 68
			3520000 // 69
	};

	Timer asdrTime = new Timer();

	Instr instr;

	private int asdrPc;

	private int tonePause;

	private int tonePc;

	private int note;

	private int freq;

	private int vol;

	void startNote(int b1, Instr i) {
		if (b1 == 0) {
			// stop
		}
		else if (b1 == 1) {
			// release
		}
		else {
			b1 -= 2;
			note = b1;

			instr = i;

			if (instr.sample != 0) {
				h.sample(instr.loop, false);
				h.freq(NOTE_FREQ[note]);
				h.vol(0x3f);
			}
			else {
				tonePause = instr.tonePause;
				tonePc = 0;

				asdrTime.init(2);
				asdrPc = 0;

				h.sample(instr.loop, true);
				freq = NOTE_FREQ[note];
				vol = 0;
			}
		}
	}

	void nextFrame() {
		if (instr.sample != 0) return;
		
		// period is wiggled or ported
		int f = freq;

		// bending
		if (tonePause != 0) {
			tonePause--;
		}
		else {
			f += instr.tone[tonePc++];
			if (tonePc == instr.tone.length) {
				tonePc = 0;
			}
		}

		h.freq(f);

		if (asdrTime.action()) {
			int dest = instr.asdr[asdrPc] & 255;
			int rate = instr.asdr[asdrPc + 1] & 255;
			vol = Math2.closer(vol, dest, rate);
			if (vol == dest && asdrPc != 6) {
				asdrPc += 2;
			}
		}
		h.freq(f);
		h.vol(vol);
	}
}
