package com.nney.tt.sounds.wav;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import com.nney.tt.sounds.Sound;

public class WaveWriter {
	// http://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
	// http://web.archive.org/web/19991115123323/http://www.borg.com/~jglatt/tech/wave.htm
	// http://sonantlive.bitsnbites.eu/tool/player.js

	static void doIt(OutputStream o, int rate, short[] content) throws IOException {
		int cl = content.length;
		cl = content.length & -16;
		WaveElementWriter w = new WaveElementWriter(o);
		int waveBytes = cl * 2;

		int l1 = waveBytes - 8;
		int l2 = l1 - 36;

		w.write32("RIFF");
		w.write32(l1);
		w.write32("WAVE");
		w.write32("fmt ");
		w.write32(16);
		w.write16(1);
		w.write16(2);
		w.write32(rate);
		w.write32(rate * 4);
		w.write16(4);
		w.write16(16);
		w.write32("data");
		w.write32(l2);
		for (int x = 0; x < cl; x++) {
			w.write16(content[x]);
		}
	}

	public static void saveWave(String name, Sound sound) {
		try {
			OutputStream fo = new BufferedOutputStream(new FileOutputStream("C:\\Users\\david\\Desktop\\z\\" + name));
			doIt(fo, sound.freq, sound.data);
			fo.close();
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
