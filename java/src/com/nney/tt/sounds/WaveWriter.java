package com.nney.tt.sounds;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

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

	public static void saveWave(String name, short[] waveForm, int frequencyInHz) {
		try {
			OutputStream fo = new BufferedOutputStream(new FileOutputStream("C:\\Users\\david\\Desktop\\z\\z\\" + name));
			doIt(fo, frequencyInHz, waveForm);
			fo.close();
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	// byte[] wave = new byte[] { 'R','I','F','F',
	// l1 & 255,(l1 >> 8) & 255,(l1 >> 16) & 255,(l1 >> 24) & 255,
	// 'W','A','V','E','f','m','t',' ',16,0,0,0,
	// 1,0, // format code
	// 2,0, // number of channels
	// 68,172,0,0, // sampling rate (blocks per second) 44100
	// 16,177,2,0, // data rate 176400
	// 4,0, // data block size
	// 16,0, // bits per sample
	// 'd','a','t','a',
	// l2 & 255,(l2 >> 8) & 255,(l2 >> 16) & 255,(l2 >> 24) & 255 };

}
