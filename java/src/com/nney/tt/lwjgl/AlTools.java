package com.nney.tt.lwjgl;

import java.nio.FloatBuffer;

import org.lwjgl.BufferUtils;
import org.lwjgl.LWJGLException;
import org.lwjgl.openal.AL;
import org.lwjgl.openal.AL10;

public class AlTools {
	public static final FloatBuffer ORIGIN = createFloatBuffer(0.0f, 0.0f, 0.0f);

	public static FloatBuffer createFloatBuffer(float... f) {
		FloatBuffer b = BufferUtils.createFloatBuffer(f.length);
		b.put(f);
		b.rewind();
		return b;
	}

	static int alCheckName(int name) {
		if (name <= 0) {
			throw new RuntimeException("Bad OpenAL name returned: " + name);
		}
		alCheck();
		return name;
	}

	static void alCheck() {
		int e = AL10.alGetError();
		if (e != AL10.AL_NO_ERROR) {
			throw new RuntimeException("Unrecoverable OpenAL error code: " + e);
		}
	}

	public static void alInit() {
		try {
			AL.create();
			AL10.alGetError();
		}
		catch (LWJGLException le) {
			throw new RuntimeException(le);
		}
		alCheck();

		// Set Listener Position
		AL10.alListener(AL10.AL_POSITION, AlTools.ORIGIN);
		AL10.alListener(AL10.AL_VELOCITY, AlTools.ORIGIN);

		// first 3 elements are "at"
		// second 3 are "up"
		FloatBuffer orientation = AlTools.createFloatBuffer(0.0f, 0.0f, -1.0f, 0.0f, 1.0f, 0.0f);
		AL10.alListener(AL10.AL_ORIENTATION, orientation);
	}

	/**
	 * We have allocated memory for our buffers and sources which needs to be
	 * returned to the system. This function frees that memory.
	 */
	public static void alShutdown() {
		AL.destroy();
	}

}
