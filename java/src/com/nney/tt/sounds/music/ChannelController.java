package com.nney.tt.sounds.music;

import com.nney.utils.Math2;

public class ChannelController {

	private final AudioChannel audioChannel;

	private final boolean goRight;

	ChannelController(AudioChannel h, boolean goRight) {
		this.audioChannel = h;
		this.goRight = goRight;
	}

	static int NOTES[] = { 0x1ac0, 0x1940, 0x17d0, 0x1680, 0x1530, 0x1400, // oct1
																			// 0
			0x12e0, 0x11d0, 0x10d0, 0x0fe0, 0x0f00, 0x0e20,

			0x0d60, 0x0ca0, 0x0be8, 0x0b40, 0x0a98, 0x0a00, // oct2 12
			0x0970, 0x08e8, 0x0868, 0x07f0, 0x0780, 0x0710,

			0x06b0, 0x0650, 0x05f4, 0x05a0, 0x054c, 0x0500, // oct3 24
			0x04b8, 0x0474, 0x0434, 0x03f8, 0x03c0, 0x0388, // <<<< 33
															// international A
															// (assuming sample
															// length 8)
			0x0358, 0x0328, 0x02fa, 0x02d0, 0x02a6, 0x0280, // oct4 36
			0x025c, 0x0234, 0x021a, 0x01fc, 0x01e0, 0x01c4, 0x01ac, 0x0194, 0x017d, 0x0168, 0x0153, 0x0140, // oct5
																											// 48
			0x012e, 0x011d, 0x010d, 0x00fe, 0x00f0, 0x00e2, 0x00d6, 0x00ca, 0x00be, 0x00b4, 0x00aa, 0x00a0, // oct6
																											// 60
			0x0097, 0x008f, 0x0087, 0x007f };

	static final int ARPEGGIOS[][] = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, { 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6 },
			{ 0, 4, 7, 0, 4, 7, 0, 4, 7, 0, 4, 7 }, { 0, 5, 9, 0, 5, 9, 0, 5, 9, 0, 5, 9 },
			{ 0, 3, 8, 0, 3, 8, 0, 3, 8, 0, 3, 8 }, { 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 },
			{ 01, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }, { 0, 0, 12, 12, 0, 0, 12, 12, 0, 0, 12, 12 },
			{ 06, 5, 4, 3, 2, 1, 6, 5, 4, 3, 2, 1 }, { 01, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6 },
			{ 0, 5, 7, 0, 5, 7, 0, 5, 7, 0, 5, 7 }, { 0, 5, 8, 0, 5, 8, 0, 5, 8, 0, 5, 8 },
			{ 0, 4, 7, 0, 4, 7, 0, 4, 7, 0, 4, 7 }, { 0, 3, 7, 0, 3, 7, 0, 3, 7, 0, 3, 7 } };

	Timer asdrTime = new Timer();

	Timer sqrTime = new Timer();

	Instr instr;

	private int asdrPosition;

	private int tonePause;

	private int tonePosition;

	private int note;

	private int period;

	private int vol;

	private SquareModifier sqr;

	private int aprPos;
	
	private int arpSelected;

	private int portSpeed;

	private int portDestination;

	void stop() {
		audioChannel.volume(0);
	}

	void release() {
		if (instr.isSynthasized()) {
			asdrPosition = 6;
			asdrTime.nextTime();
		}
		else {
			audioChannel.volume(0);
		}
	}

	void startNote(Instr i, int n) {
		boolean changeOfInstrument = i!=instr;
		instr = i;
		assert instr != null;

		note = n;

		if (!instr.isSynthasized()) {
			audioChannel.wave(instr.loop, false);
			audioChannel.period(NOTES[note]);
			audioChannel.volume(AudioChannel.MAXIMUM_VOLUME);
		}
		else {
//			System.out.println("START NOTE " + n);
//			instr.dump();

			tonePause = instr.tonePause;
			tonePosition = 0;

			asdrTime.everyAndNextTime(3);
			asdrPosition = 0;

			if (instr.sqrRate != 0) {
				sqrTime.every(instr.sqrRate);
				if (changeOfInstrument) {
					sqr = new SquareModifier(instr.loop, instr.sqrBegin, instr.sqrEnd, goRight);
				}
				audioChannel.wave(sqr.read(), true);
			}
			else {
				sqrTime.every(0);
				audioChannel.wave(instr.loop, true);
			}

			period = NOTES[note];
			vol = 0;
		}
	}

	void update() {
		if (instr==null || !instr.isSynthasized()) return;

		// period is wiggled /or/ ported
		int p = period;

		if (portSpeed != 0 && p != portDestination) {
			asdrPosition = 0;
			p = period = Math2.closer(p, portDestination, portSpeed);
		}
		else {
			p = NOTES[note+ARPEGGIOS[arpSelected][aprPos]];
			aprPos ++;
			aprPos %= 12;
		}

		if (sqrTime.isTime()) {
			sqr.modify();
		}

		// bending
		if (tonePause != 0) {
			tonePause--;
		}
		else {
			p += instr.tone[tonePosition];
			tonePosition += 2;
			if (tonePosition >= instr.tone.length) {
				tonePosition = 0;
			}
		}

		if (asdrTime.isTime()) {
//			System.out.println("yes");
			int dest = instr.asdr[asdrPosition] & 255;
			dest *= 4;
			int rate = instr.asdr[asdrPosition + 1] & 255;
			int nvol = Math2.closer(vol, dest, rate);
//			System.out.println(String
//					.format("asdrPosition%d dest%d rate%d %d->%d", asdrPosition, dest, rate, vol, nvol));
			vol = nvol;
			if (vol == dest && asdrPosition != 6) {
				asdrPosition += 2;
			}
		}
		else {
//			System.out.println("no");
		}

		audioChannel.period(p);
		audioChannel.volume(vol);
	}

	public void chooseArp(int param) {
		if (param>=ARPEGGIOS.length) {
			param = 0;
		}
		arpSelected = param;
	}
}
