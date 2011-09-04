package com.nney.tt.sounds;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.nio.ShortBuffer;

import org.lwjgl.BufferUtils;
import org.lwjgl.LWJGLException;
import org.lwjgl.openal.AL;
import org.lwjgl.openal.AL10;

import com.nney.utils.Math2;

public class Speaker {

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

	
	private void play(short[] z, int rate) {
		ByteBuffer bb = BufferUtils.createByteBuffer(z.length * 2);
		bb.order(ByteOrder.nativeOrder());
		ShortBuffer sb = bb.asShortBuffer();
		for (int x = 0; x < z.length; x++) {
			sb.put((short) z[x]);
		}

		buffer = alCheckName(AL10.alGenBuffers());
		AL10.alBufferData(buffer, AL10.AL_FORMAT_STEREO16, bb, rate);

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

	private int alCheckName(int name) {
		if (name <= 0) {
			throw new RuntimeException("Bad OpenAL name returned: " + name);
		}
		alCheck();
		return name;
	}

	private void alCheck() {
		int e = AL10.alGetError();
		if (e != AL10.AL_NO_ERROR) {
			throw new RuntimeException("Unrecoverable OpenAL error code: " + e);
		}
	}

	/**
	 * void setListenerValues()
	 * 
	 * We already defined certain values for the Listener, but we need to tell
	 * OpenAL to use that data. This function does just that.
	 */
	private void setListenerValues() {
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
	private void killALData() {
		AL10.alDeleteSources(source);
		AL10.alDeleteBuffers(buffer);
	}

	private void alInit() {
		try {
			AL.create();
			AL10.alGetError();
		}
		catch (LWJGLException le) {
			throw new RuntimeException(le);
		}
	}


	private void properDemo() {
		short[] z = new short[44100];
		int p = 320;
		int c = 0x5000;
		for (int x=0; x<z.length; x++) {
			z[x] = (short) (((x%p)<(p/2)) ? c : -c);
		}
		play(z, 44100);
	}

	public void execute() {
		alInit();
		properDemo();
		killALData();
		AL.destroy();
	}

	public static void main(String[] args) {
		new Speaker().execute();
	}

}
