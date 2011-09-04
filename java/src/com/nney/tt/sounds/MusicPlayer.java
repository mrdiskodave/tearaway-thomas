package com.nney.tt.sounds;

import java.util.ArrayList;

import com.nney.tt.resources.TTResource;
import com.nney.utils.Math2;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class MusicPlayer {
	static final int FREQUENCY = 44100;

	private static final int SEGMENT_SIZE = FREQUENCY / 52;

	private static final int CHANNEL_COUNT = 4;

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

	private void configuredSaveSong(SongSlice bn) {
		String saveName = songName + bn.extraName() + ".wav";
		System.out.println("=== " + saveName);
		WaveWriter.saveWave(saveName, generateSlice(bn).collect(), FREQUENCY);
	}

	private void setUpSong(String s) {
		loadSong(s);
		loadInstruments();
		generateConfigs();
	}
	

	private SampleStore generateSlice(SongSlice bn) {
		if (!bn.isContinuing()) {
			generatePlayers();
		}
		byte[] sequence = song.getSequence();
		ArrayList<Integer> blockNumbers = new ArrayList<Integer>();
		bn.getThem(blockNumbers, sequence);

		int leadOut = bn.leadOut() ? 64 : 0;
		int steps = 0;
		for (int b = 0; b < blockNumbers.size(); b++) {
			steps += new Block(song, blockNumbers.get(b)).lines;
		}
		steps += leadOut;
		int clickLength = song.clickLength();
		steps *= clickLength;
		steps *= SEGMENT_SIZE;

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

		return sampleStore;
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
				
				int ileft = Math2.limit(Short.MIN_VALUE + 2, Short.MAX_VALUE - 2, (int) (left * 170));
				int iright = Math2.limit(Short.MIN_VALUE + 2, Short.MAX_VALUE - 2, (int) (right * 170));
				sampleStore.add((short) ileft, (short) iright);
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


	public static void main(String[] args) {
		new MusicPlayer().execute();
	}

	public void execute() {
		properDemo();
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

