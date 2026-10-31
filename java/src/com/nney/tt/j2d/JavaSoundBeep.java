package com.nney.tt.j2d;

import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.DataLine;
import javax.sound.sampled.Mixer;
import javax.sound.sampled.SourceDataLine;

/**
 * A sound test: one second of 440Hz through javax.sound, the way the game
 * plays its sound, with the devices Java can see. (java -jar
 * tearaway-thomas.jar --beep)
 */
final class JavaSoundBeep {
	private JavaSoundBeep() {
	}

	static void run() {
		int rate = SoundAudioContext.RATE;
		AudioFormat fmt = new AudioFormat(rate, 16, 2, true, false);
		System.out.println("Java " + System.getProperty("java.version") + " on " + System.getProperty("os.name"));
		System.out.println("Devices that can play it:");
		for (Mixer.Info mi : AudioSystem.getMixerInfo()) {
			try {
				Mixer m = AudioSystem.getMixer(mi);
				if (m.isLineSupported(new DataLine.Info(SourceDataLine.class, fmt))) {
					System.out.println("  " + mi.getName() + " (" + mi.getDescription() + ")");
				}
			}
			catch (Throwable e) {
				System.out.println("  " + mi.getName() + ": " + e);
			}
		}
		try {
			SourceDataLine line = AudioSystem.getSourceDataLine(fmt);
			line.open(fmt);
			line.start();
			System.out.println("Playing on the default device (Windows: \"Primary Sound Driver\")");
			byte[] b = new byte[rate * 4];
			for (int i = 0; i < rate; i++) {
				short s = (short) (Math.sin(2 * Math.PI * 440 * i / rate) * 16000);
				b[i * 4] = b[i * 4 + 2] = (byte) s;
				b[i * 4 + 1] = b[i * 4 + 3] = (byte) (s >> 8);
			}
			System.out.println("BEEP (one second)...");
			line.write(b, 0, b.length);
			line.drain();
			line.close();
			System.out.println("Done. Did you hear it?");
		}
		catch (Throwable e) {
			System.out.println("Couldn't play: " + e);
		}
	}
}
