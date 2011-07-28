package com.nney.tt.sounds;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.nio.ShortBuffer;
import java.util.ArrayList;

import org.lwjgl.BufferUtils;
import org.lwjgl.LWJGLException;
import org.lwjgl.openal.AL;
import org.lwjgl.openal.AL10;

import com.nney.tt.resources.TTResource;
import com.nney.utils.Math2;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class MusicPlayer {
	static final int FREQUENCY = 44100;

	private static final int SEGMENT_SIZE = FREQUENCY / 52;

	private static final int CHANNEL_COUNT = 4;

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
	// only using 1, 2, 3, 5, 6, 7, 8, 10 and 14!!

	private ChannelConfig[] configs;

	private ChannelPlayer[] players;

	private Song song;

	private String songName;

	private void properDemo() {
		saveSong("intro");
		saveSong("wood");
		saveSong("toy");
		saveSong("ice");
		saveSong("future");
		// saveSong("unused");

		// 0=game over 1=a new world 2=level complete 3=level begin

		setUpSong("jingle");
		configuredSaveSong(new JingleSongSlice("gameover", 0));
		configuredSaveSong(new JingleSongSlice("startworld", 1));
		configuredSaveSong(new JingleSongSlice("levelcomplete", 2));
		configuredSaveSong(new JingleSongSlice("levelbegin", 3));
	}

	abstract class SongSlice {
		abstract void getThem(ArrayList<Integer> blockNumbers, byte[] sequence);

		boolean leadOut() {
			return false;
		}

		String extraName() {
			return "";
		}

		boolean isContinuing() {
			return false;
		}
	}

	class EntireSongSlice extends SongSlice {
		@Override
		public void getThem(ArrayList<Integer> blockNumbers, byte[] sequence) {
			for (int b = 0; b < sequence.length; b++) {
				blockNumbers.add((int) sequence[b]);
			}
		}

		@Override
		boolean leadOut() {
			return true;
		}
	}

	class FirstBlockSongSlice extends SongSlice {
		@Override
		public void getThem(ArrayList<Integer> blockNumbers, byte[] sequence) {
			blockNumbers.add((int) sequence[0]);
		}

		@Override
		String extraName() {
			return "-begin";
		}
	}

	class LoopSongSlice extends SongSlice {
		@Override
		public void getThem(ArrayList<Integer> blockNumbers, byte[] sequence) {
			for (int b = 1; b < sequence.length; b++) {
				blockNumbers.add((int) sequence[b]);
			}
			blockNumbers.add((int) sequence[0]);
		}

		@Override
		String extraName() {
			return "-loop";
		}

		@Override
		boolean isContinuing() {
			return true;
		}
	}

	class JingleSongSlice extends SongSlice {
		private final String name;
		private final int number;

		JingleSongSlice(String name, int number) {
			this.name = name;
			this.number = number;
		}

		@Override
		void getThem(ArrayList<Integer> blockNumbers, byte[] sequence) {
			blockNumbers.add((int) sequence[number]);
		}

		@Override
		String extraName() {
			return "-" + name;
		}

		@Override
		boolean leadOut() {
			return true;
		}
	}

	private void saveSong(String s) {
		setUpSong(s);
		// configuredSaveSong(new EntireSongSlice());
		configuredSaveSong(new FirstBlockSongSlice());
		configuredSaveSong(new LoopSongSlice());
	}

	private void setUpSong(String s) {
		loadSong(s);
		loadInstruments();
		generateConfigs();
	}

	private void configuredSaveSong(SongSlice bn) {
		if (!bn.isContinuing()) {
			generatePlayers();
		}
		byte[] sequence = song.getSequence();
		ArrayList<Integer> blockNumbers = new ArrayList<Integer>();
		bn.getThem(blockNumbers, sequence);

		int leadOut = bn.leadOut() ? 32 : 0;
		int steps = 0;
		for (int b = 0; b < blockNumbers.size(); b++) {
			steps += new Block(song, blockNumbers.get(b)).lines;
		}
		steps += leadOut;
		int clickLength = song.clickLength();
		steps *= clickLength;
		steps *= SEGMENT_SIZE;

		String saveName = songName + bn.extraName() + ".wav";
		System.out.println("=== " + saveName);

		SampleStore sampleStore = new SampleStore(steps);

		for (int b = 0; b < blockNumbers.size(); b++) {
			Block block = new Block(song, blockNumbers.get(b));
			for (int line = 0; line < block.lines; line++) {
				int index = block.lineOffset(line);
				for (int c = 0; c < CHANNEL_COUNT; c++) {
					int n = block.data[index++];
					int i = block.data[index++];
					int ap = block.data[index++];
					players[c].play(n, i, ap);
				}
				saveClick(players, clickLength, sampleStore);
			}
		}

		for (int x = 0; x < leadOut; x++) {
			saveClick(players, clickLength, sampleStore);
		}
		if (leadOut != 0) sampleStore.rewindOverSilence();

		sampleStore.dumpRange();

		short[] productionWave = sampleStore.collect();
		WaveWriter.saveWave(saveName, productionWave, FREQUENCY);
		// System.out.println("play");
		// play(productionWave, FREQUENCY);
		// System.out.println("stop");
	}

	private void loadSong(String s) {
		songName = s;
		song = new Song(new DataSrc(OpenableTools.mustLoad(TTResource.sound(songName + ".song"))));
	}

	private void generatePlayers() {
		players = new ChannelPlayer[CHANNEL_COUNT];
		assert configs.length == CHANNEL_COUNT;
		for (int x = 0; x < CHANNEL_COUNT; x++) {
			players[x] = new ChannelPlayer(this, configs[x]);
		}
	}

	private void generateConfigs() {
		configs = new ChannelConfig[] { new ChannelConfig(0.25f, true), // 0
				new ChannelConfig(0.75f, true), // 1
				new ChannelConfig(0.75f, true), // 2
				new ChannelConfig(0.25f, true), // 3
		};
	}

	private void saveClick(ChannelPlayer[] players, int clickLength, SampleStore sampleStore) {
		for (int click = 0; click < clickLength; click++) {
			for (int c = 0; c < CHANNEL_COUNT; c++) {
				players[c].update();
			}
			for (int t = 0; t < SEGMENT_SIZE; t++) {
				float left = 0;
				float right = 0;
				for (ChannelPlayer player : players) {
					if (player.config.enabled) {
						int s = player.sample();
						float pos = player.config.position;
						left += s * (1f - pos);
						right += s * pos;
					}
				}
				left = Math2.limit(Short.MIN_VALUE + 2, Short.MAX_VALUE - 2, (int) (left * 170));
				right = Math2.limit(Short.MIN_VALUE + 2, Short.MAX_VALUE - 2, (int) (right * 170));

				sampleStore.add((short) left, (short) right);
			}
		}
	}

	private void loadInstruments() {
		//
		// load the samples
		//
		byte[][] sample = new byte[9][];
		for (int s = 0; s < sample.length; s++) {
			Openable sampleOpenable = TTResource.sound(String.format("samp%s.bin", s + 1));
			sample[s] = OpenableTools.mustLoad(sampleOpenable);
		}

		//
		// load the instruments

		byte[] iblk = OpenableTools.mustLoad(TTResource.sound("iblk"));
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
	}

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
		new MusicPlayer().execute();
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
		if (answer == null) {
			System.out.println("Instrument " + b2 + " not found!");
		}
		return answer;
	}
}

// TODO: make it stop only after instr have faded out
// TODO: look at audiocompression (lesser freq? lesser bits?)
// TODO: look at smooth looping (reset instr and recapture the first block)

