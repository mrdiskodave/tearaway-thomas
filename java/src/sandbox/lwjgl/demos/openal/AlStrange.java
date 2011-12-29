package sandbox.lwjgl.demos.openal;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.nio.ShortBuffer;

import org.lwjgl.BufferUtils;
import org.lwjgl.LWJGLException;
import org.lwjgl.openal.AL;
import org.lwjgl.openal.AL10;

import com.nney.tt.sounds.Sound;
import com.nney.tt.sounds.wav.WaveWriter;

/**
 * This is very odd. The code below plays six 440hz tones. Each tone is played
 * using a longer wave form but also a faster frequency so the tone still comes
 * out at 440hz. Now here is the odd bit: each successive tone is [b]louder[/b].
 * What gives?
 */
public class AlStrange {
	// originally from
	// http://lwjgl.org/documentation_openal_01.php

	static FloatBuffer createFloatBuffer(float... f) {
		FloatBuffer b = BufferUtils.createFloatBuffer(f.length);
		b.put(f);
		b.rewind();
		return b;
	}

	/** Buffers hold sound data. */
	int buffer;

	/** Sources are points emitting sound. */
	int source;

	/** Position of the source sound. */
	FloatBuffer sourcePos = createFloatBuffer(0.0f, 0.0f, 0.0f);

	/** Velocity of the source sound. */
	FloatBuffer sourceVel = createFloatBuffer(0.0f, 0.0f, 0.0f);

	/** Position of the listener. */
	FloatBuffer listenerPos = createFloatBuffer(0.0f, 0.0f, 0.0f);

	/** Velocity of the listener. */
	FloatBuffer listenerVel = createFloatBuffer(0.0f, 0.0f, 0.0f);

	/**
	 * Orientation of the listener. (first 3 elements are "at", second 3 are
	 * "up")
	 */
	FloatBuffer listenerOri = createFloatBuffer(0.0f, 0.0f, -1.0f, 0.0f, 1.0f, 0.0f);

	/**
	 * Throw if we've been given a bad name.
	 * 
	 * @param name
	 * @return Just passes through the given name for convenience.
	 */
	private int alCheckName(int name) {
		if (name <= 0) {
			throw new RuntimeException("Bad OpenAL name returned: " + name);
		}
		alCheck();
		return name;
	}

	/**
	 * Throw any <code>AL10.alGetError()</code>s that have happened.
	 */
	private void alCheck() {
		int e = AL10.alGetError();
		if (e != AL10.AL_NO_ERROR) {
			throw new RuntimeException("Unrecoverable OpenAL error code: " + e);
		}
	}

	interface WaveCreator {
		short[] makeWave(int waveLength);

		String waveName();
	}

	int counter = 0;

	private void playTone(WaveCreator wc, int waveLengthInBytes) {
		int frequencyInHz = 110 * waveLengthInBytes;
		int timeInSeconds = 2;

		short[] waveForm = wc.makeWave(waveLengthInBytes);

		StringBuffer sb = new StringBuffer();
		for (int x = 0; x < waveForm.length; x++) {
			if (x != 0) {
				sb.append(',');
			}
			sb.append(waveForm[x]);
		}
		String name = String.format("%02d-%s-%shz-%ssamplesPerCycle.wav", counter++, wc.waveName(), frequencyInHz,
				waveLengthInBytes);
		System.out.println("Filename  : " + name);
		System.out.println("Waveform  : " + sb + " (length=" + waveLengthInBytes + ")");
		System.out.println();

		short[] sample = new short[frequencyInHz * timeInSeconds];
		for (int x = 0; x < sample.length; x++) {
			sample[x] = waveForm[x % waveForm.length];
		}
		playWave(sample, frequencyInHz);
		WaveWriter.saveWave(name, new Sound(sample, frequencyInHz));
	}

	class SquareWave implements WaveCreator {
		@Override
		public short[] makeWave(int waveLength) {
			short[] answer = new short[waveLength];
			for (int x = 0; x < waveLength; x++) {
				answer[x] = (short) (x < (waveLength / 2) ? 20000 : -20000);
			}
			return answer;
		}

		@Override
		public String waveName() {
			return "square";
		}
	}

	class SineWave implements WaveCreator {
		@Override
		public short[] makeWave(int waveLength) {
			short[] answer = new short[waveLength];
			for (int x = 0; x < waveLength; x++) {
				double d = Math.sin(((Math.PI * 2 * x) / waveLength)) * 20000;
				answer[x] = (short) d;
			}
			return answer;
		}

		@Override
		public String waveName() {
			return "sine";
		}
	}

	private void playWave(short[] wave, int rate) {
		ByteBuffer bb = BufferUtils.createByteBuffer(wave.length * 2);
		bb.order(ByteOrder.nativeOrder());
		ShortBuffer sb = bb.asShortBuffer();
		for (int x = 0; x < wave.length; x++) {
			sb.put(wave[x]);
		}

		buffer = alCheckName(AL10.alGenBuffers());
		AL10.alBufferData(buffer, AL10.AL_FORMAT_MONO16, bb, rate);

		// Bind the buffer with the source.
		source = alCheckName(AL10.alGenSources());
		AL10.alSourcei(source, AL10.AL_BUFFER, buffer);
		AL10.alSourcef(source, AL10.AL_PITCH, 1.0f);
		AL10.alSourcef(source, AL10.AL_GAIN, 1.0f);
		AL10.alSource(source, AL10.AL_POSITION, sourcePos);
		AL10.alSource(source, AL10.AL_VELOCITY, sourceVel);
		alCheck();

		setListenerValues();

		AL10.alSourcePlay(source);

		do {
			try {
				Thread.sleep(5);
			}
			catch (InterruptedException e) {
				// ignored
			}
		} while (AL10.alGetSourcei(source, AL10.AL_SOURCE_STATE) == AL10.AL_PLAYING);
	}

	/**
	 * void setListenerValues()
	 * 
	 * We already defined certain values for the Listener, but we need to tell
	 * OpenAL to use that data. This function does just that.
	 */
	void setListenerValues() {
		AL10.alListener(AL10.AL_POSITION, listenerPos);
		AL10.alListener(AL10.AL_VELOCITY, listenerVel);
		AL10.alListener(AL10.AL_ORIENTATION, listenerOri);
	}

	/**
	 * void killALData()
	 * 
	 * We have allocated memory for our buffers and sources which needs to be
	 * returned to the system. This function frees that memory.
	 */
	void killALData() {
		AL10.alDeleteSources(source);
		AL10.alDeleteBuffers(buffer);
	}

	public void execute() {
		try {
			AL.create();
			alCheck();
		}
		catch (LWJGLException le) {
			throw new RuntimeException(le);
		}

		outputWaves(new SineWave());
		outputWaves(new SquareWave());

		killALData();
		AL.destroy();
	}

	private void outputWaves(WaveCreator wave) {
		int waveLengthInBytes = 2;
		for (int x = 0; x < 9; x++) {
			playTone(wave, waveLengthInBytes);
			waveLengthInBytes *= 2;
		}
	}

	public static void main(String[] args) {
		new AlStrange().execute();
	}
}
