package com.nney.tt.j2d;

import java.util.ArrayList;

import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.DataLine;
import javax.sound.sampled.Mixer;
import javax.sound.sampled.SourceDataLine;

import com.nney.tt.gfx.Disposable;
import com.nney.tt.sounds.AudioContext;
import com.nney.tt.sounds.Loop;
import com.nney.tt.sounds.Sound;

/**
 * An {@link AudioContext} using the JDK's own javax.sound, so no native
 * libraries are needed.
 *
 * A small software mixer combines the music and the current sound effect
 * (like the OpenAL version, only one effect plays at a time) and resamples
 * everything to 44.1kHz stereo.
 */
public class SoundAudioContext implements AudioContext, Disposable {
	public static final int RATE = 44100;
	private static final int SIMULTANEOUS_FX = 1;
	private static final int CHUNK_FRAMES = 512;
	private static final float MASTER_GAIN = 0.7f;
	private static final float KNEE = 0.8f;

	/** A playing sound: a position within some stereo 16 bit data. */
	private static final class Voice {
		final Sound sound;
		final float vol;
		final double step;
		double pos; // in frames

		Voice(Sound sound, float vol) {
			this.sound = sound;
			this.vol = vol;
			this.step = (double) sound.freq / RATE;
		}

		int frames() {
			return sound.data.length / 2;
		}

		boolean finished() {
			return pos >= frames();
		}

		/** Add up to n frames into acc; returns how many were produced. */
		int mixInto(float[] acc, int offset, int n, float gain) {
			short[] d = sound.data;
			int total = frames();
			int made = 0;
			float g = gain * vol;
			while (made < n && pos < total) {
				int i = (int) pos;
				float frac = (float) (pos - i);
				int j = Math.min(i + 1, total - 1);
				float l = d[i * 2] + (d[j * 2] - d[i * 2]) * frac;
				float r = d[i * 2 + 1] + (d[j * 2 + 1] - d[i * 2 + 1]) * frac;
				acc[(offset + made) * 2] += l * g;
				acc[(offset + made) * 2 + 1] += r * g;
				pos += step;
				made++;
			}
			return made;
		}
	}

	private final Loop[] musics = new Loop[SLOTS];
	private final ArrayList<Sound> effectSounds = new ArrayList<>();
	private final ArrayList<Float> effectVols = new ArrayList<>();

	// guarded by "this"
	private Loop playing;
	private Voice musicVoice;
	private boolean inLoopPart;
	private float musicVol = 1;
	private final ArrayList<Voice> effects = new ArrayList<>();

	private SourceDataLine line;
	private Thread thread;
	private volatile boolean running;

	/**
	 * @param useDevice
	 *            <code>false</code> to never open a sound device (headless
	 *            runs); {@link #mix(short[], int)} can still be called.
	 */
	public SoundAudioContext(boolean useDevice) {
		this(useDevice, null);
	}

	/**
	 * @param deviceText
	 *            Part of the name of the sound device to use (as --beep lists
	 *            them), or null for the default.
	 */
	public SoundAudioContext(boolean useDevice, String deviceText) {
		if (useDevice) openDevice(deviceText);
	}

	/** The game's sound: 44.1kHz, 16 bit stereo. */
	static AudioFormat format() {
		return new AudioFormat(RATE, 16, 2, true, false);
	}

	/** The devices that can play the game's sound. */
	static java.util.List<Mixer.Info> devices() {
		java.util.List<Mixer.Info> answer = new java.util.ArrayList<Mixer.Info>();
		for (Mixer.Info mi : AudioSystem.getMixerInfo()) {
			try {
				if (AudioSystem.getMixer(mi).isLineSupported(new DataLine.Info(SourceDataLine.class, format()))) {
					answer.add(mi);
				}
			}
			catch (RuntimeException e) {
				// not one we can use
			}
		}
		return answer;
	}

	/**
	 * The first device whose name has this in it (ignoring case), or null
	 * (none asked for, or none matches: then say so).
	 */
	static Mixer.Info findDevice(String text) {
		if (text == null) return null;
		for (Mixer.Info mi : devices()) {
			if (mi.getName().toLowerCase().contains(text.toLowerCase())) return mi;
		}
		System.out.println("No sound device has \"" + text + "\" in its name; using the default");
		return null;
	}

	/** A line to play the game's sound on that device (or the default). */
	static SourceDataLine openLine(Mixer.Info device) throws Exception {
		AudioFormat fmt = format();
		SourceDataLine l = device != null ? AudioSystem.getSourceDataLine(fmt, device) : AudioSystem.getSourceDataLine(fmt);
		System.out.println("Sound: " + (device != null ? device.getName() : "the default device"));
		return l;
	}

	private void openDevice(String deviceText) {
		try {
			AudioFormat fmt = format();
			line = openLine(findDevice(deviceText));
			line.open(fmt, CHUNK_FRAMES * 4 * 8);
			line.start();
		}
		catch (Exception e) {
			System.err.println("No sound available: " + e);
			line = null;
			return;
		}
		running = true;
		thread = new Thread(new Runnable() {
			@Override
			public void run() {
				short[] buf = new short[CHUNK_FRAMES * 2];
				byte[] bytes = new byte[CHUNK_FRAMES * 4];
				while (running) {
					mix(buf, CHUNK_FRAMES);
					for (int i = 0; i < buf.length; i++) {
						bytes[i * 2] = (byte) buf[i];
						bytes[i * 2 + 1] = (byte) (buf[i] >> 8);
					}
					line.write(bytes, 0, bytes.length);
				}
			}
		}, "tt-audio");
		thread.setDaemon(true);
		thread.setPriority(Thread.MAX_PRIORITY);
		thread.start();
	}

	/**
	 * Produce the next n stereo frames of output (interleaved L,R).
	 */
	public void mix(short[] out, int n) {
		float[] acc = new float[n * 2];
		synchronized (this) {
			int done = 0;
			while (musicVoice != null && done < n) {
				done += musicVoice.mixInto(acc, done, n - done, musicVol);
				if (musicVoice.finished()) {
					if (playing != null && playing.hasLoop()) {
						double over = musicVoice.pos - musicVoice.frames();
						musicVoice = new Voice(playing.loop, 1);
						musicVoice.pos = Math.max(0, over);
						inLoopPart = true;
					}
					else {
						musicVoice = null;
					}
				}
			}
			for (int x = effects.size() - 1; x >= 0; x--) {
				Voice v = effects.get(x);
				v.mixInto(acc, 0, n, 1);
				if (v.finished()) effects.remove(x);
			}
		}
		// The music is mastered at full scale, so leave headroom for effects
		// and round off anything that would still clip.
		for (int i = 0; i < acc.length; i++) {
			float s = acc[i] * MASTER_GAIN / 32768f;
			float a = Math.abs(s);
			if (a > KNEE) {
				float over = (a - KNEE) / (1 - KNEE);
				a = KNEE + (1 - KNEE) * (over / (1 + over));
				s = Math.signum(s) * a;
			}
			out[i] = (short) Math.round(s * 32767f);
		}
	}

	@Override
	public synchronized void loadMusic(int slot, Loop music) {
		stopMusic();
		musics[slot] = music;
	}

	@Override
	public synchronized void startMusic(int slot) {
		stopMusic();
		playing = musics[slot];
		if (playing == null) throw new IllegalStateException("Slot " + slot + " is empty");
		musicVoice = new Voice(playing.begin, 1);
		inLoopPart = false;
	}

	@Override
	public synchronized void setMusicVolume(float vol) {
		musicVol = vol;
	}

	@Override
	public synchronized void stopMusic() {
		playing = null;
		musicVoice = null;
	}

	@Override
	public synchronized void loadEffect(float vol, Sound sound) {
		effectSounds.add(sound);
		effectVols.add(vol);
	}

	@Override
	public synchronized void playEffect(int x) {
		effects.add(new Voice(effectSounds.get(x), effectVols.get(x)));
		while (effects.size() > SIMULTANEOUS_FX) {
			effects.remove(0);
		}
	}

	public synchronized boolean isMusicLooping() {
		return inLoopPart;
	}

	@Override
	public void close() {
		running = false;
		if (thread != null) {
			try {
				thread.join(500);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
		if (line != null) {
			line.stop();
			line.close();
		}
	}
}
