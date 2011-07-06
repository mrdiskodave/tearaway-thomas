package sandbox.lwjgl.demos;

import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.util.Scanner;

import org.lwjgl.BufferUtils;
import org.lwjgl.LWJGLException;
import org.lwjgl.openal.AL;
import org.lwjgl.openal.AL10;
import org.lwjgl.util.WaveData;

import com.nney.utils.FileOpenable;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class Lesson1 {
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
	 * boolean LoadALData()
	 * 
	 * This function will load our sample data from the disk using the Alut
	 * utility and send the data into OpenAL as a buffer. A source is then also
	 * created to play that buffer.
	 */
	void loadALData() {
		// Load wav data into a buffer.
		buffer = alCheckName(AL10.alGenBuffers());

		byte[] data = OpenableTools.mustLoad(new FileOpenable("C:\\Users\\david\\Desktop\\newdata\\Test.wav"));
		WaveData waveFile = WaveData.create(data);
		AL10.alBufferData(buffer, waveFile.format, waveFile.data, waveFile.samplerate);
		waveFile.dispose();

		// Bind the buffer with the source.
		source = alCheckName(AL10.alGenSources());
		AL10.alSourcei(source, AL10.AL_BUFFER, buffer);
		AL10.alSourcef(source, AL10.AL_PITCH, 1.0f);
		AL10.alSourcef(source, AL10.AL_GAIN, 1.0f);
		AL10.alSource(source, AL10.AL_POSITION, sourcePos);
		AL10.alSource(source, AL10.AL_VELOCITY, sourceVel);
		alCheck();
	}

	private int alCheckName(int name) {
		if (name<=0) {
			throw new RuntimeException("Bad OpenAL name returned: "+name);
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

	public static void main(String[] args) {
		new Lesson1().execute();
	}

	public void execute() {
		try {
			AL.create();
			AL10.alGetError();
		}
		catch (LWJGLException le) {
			throw new RuntimeException(le);
		}

		
		loadALData();

		setListenerValues();

		// Loop.
		System.out.println("OpenAL Tutorial 1 - Single Static Source");
		System.out.println("[Menu]");
		System.out.println("p - Play the sample.");
		System.out.println("s - Stop the sample.");
		System.out.println("h - Pause the sample.");
		System.out.println("q - Quit the program.");
		char c = ' ';
		Scanner stdin = new Scanner(System.in);
		while (c != 'q') {
			try {
				System.out.print("Input: ");
				c = (char) stdin.nextLine().charAt(0);
			}
			catch (Exception ex) {
				c = 'q';
			}

			switch (c) {
			// Pressing 'p' will begin playing the sample.
			case 'p':
				AL10.alSourcePlay(source);
				break;

			// Pressing 's' will stop the sample from playing.
			case 's':
				AL10.alSourceStop(source);
				break;

			// Pressing 'h' will pause the sample.
			case 'h':
				AL10.alSourcePause(source);
				break;
			}
		}
		killALData();
		
		AL.destroy();
	}
}
