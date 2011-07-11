package sandbox.lwjgl.demos.openal;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.ShortBuffer;
import java.util.Scanner;

import org.lwjgl.BufferUtils;
import org.lwjgl.LWJGLException;
import org.lwjgl.openal.AL;
import org.lwjgl.openal.AL10;
import org.lwjgl.util.WaveData;

import com.nney.utils.ClassResourceOpenable;
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

	private Instr[] instrs;

	private void properDemo() {

		//
		// load the samples
		//
		byte[][] sample = new byte[3][];
		for (int s = 0; s < 3; s++) {
			Openable sampleOpenable = new ClassResourceOpenable(Lesson1.class, String.format("samp%s.bin", s + 1));
			sample[s] = OpenableTools.mustLoad(sampleOpenable);
		}

		//
		// load the instruments

		byte[] iblk = OpenableTools.mustLoad(new ClassResourceOpenable(Lesson1.class, "iblk"));
		instrs = new Instr[16];
		for (int x = 0; x < 16; x++) {
			instrs[x] = new Instr(new DataSrc(iblk, x * 94, 94));
		}

		//
		// bind the samples
		//
		for (Instr i : instrs) {
			i.bind(sample);
		}

		//
		// load a song
		//
		Song song = new Song(
				new DataSrc(OpenableTools.mustLoad(new ClassResourceOpenable(Lesson1.class, "intro.song"))));

		AudioChannel c = new AudioChannel();

		ChannelController cc = new ChannelController(c);
		ChannelPlayer cp = new ChannelPlayer(cc, this);

		Timer clickTime = new Timer();
		clickTime.everyAndNow(song.clickLength());

		int rate = 44100;
		int len = rate * 30;
		int[] z = new int[len];
		byte[] sequence = song.getSequence();

		SongPosition sp = new SongPosition();

		for (int t = 0; t < len; t++) {
			if (t % (rate/10) == 0) {
				if (clickTime.isTime()) {
					byte blkIdx = sequence[sp.seq];
					byte[] blk = song.block(blkIdx);
					assert blk.length % 12 == 0;
					int lines = blk.length / 12;

					int index = sp.line * 12 + 6;

					int n = blk[index++];
					int i = blk[index++];
					int ap = blk[index++];
					System.out.println(String.format("seq[%02d]=%02d,#%03d n%d,i%d,ap%d", sp.seq, blkIdx, sp.line, n, i, ap));

					cp.play(n, i, ap);

					sp.line++;
					if (sp.line >= lines) {
						sp.line = 0;
						sp.seq++;
						if (sp.seq >= sequence.length) {
							sp.seq = 0;
						}
					}
				}
				else {
					System.out.println("JUST UPDATE");
				}
				cc.update();
			}
			z[t] = c.sample();
		}

		play(z, rate);
	}

	private void play(int[] z, int rate) {
		ByteBuffer bb = BufferUtils.createByteBuffer(z.length * 2);
		bb.order(ByteOrder.nativeOrder());
		ShortBuffer sb = bb.asShortBuffer();
		for (int x = 0; x < z.length; x++) {
			int s = z[x];
			s *= 256;
			sb.put((short) s);
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

		properDemo();

		killALData();

		AL.destroy();
	}

	public Instr findInstr(int b2) {
		Instr answer = instrs[b2];
		if (answer==null) {
			System.out.println("Instrument "+b2+" not found!");
		}
		return answer;
	}
}
