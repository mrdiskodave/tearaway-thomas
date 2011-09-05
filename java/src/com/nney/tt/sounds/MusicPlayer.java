package com.nney.tt.sounds;

import java.util.ArrayList;

import com.nney.tt.resources.TTResource;
import com.nney.utils.Math2;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class MusicPlayer {
	class Loop {
		public final SampleStore begin;
		public final SampleStore loop;

		Loop(SampleStore begin, SampleStore loop) {
			this.begin = begin;
			this.loop = loop;
		}
	}

	static abstract class SongSlice {
		int first() { return 0; }
		int last() { return Integer.MAX_VALUE; }

		boolean leadOut() {
			return false;
		}

		boolean isContinuing() {
			return false;
		}
	}

	class EntireSongSlice extends SongSlice {
		@Override
		boolean leadOut() {
			return true;
		}
	}

	static class FirstBlockSongSlice extends SongSlice {
		@Override
		int last() {
			return 1;
		}
	}

	static class LoopSongSlice extends SongSlice {
		@Override
		int first() {
			return 1;
		}

		@Override
		boolean isContinuing() {
			return true;
		}
	}

	static class JingleSongSlice extends SongSlice {
		private final int number;

		JingleSongSlice(int number) {
			this.number = number;
		}

		@Override
		int first() {
			return number;
		}
		
		@Override
		int last() {
			return number+1;
		}

		@Override
		boolean leadOut() {
			return true;
		}
	}



	
	
	static final int FREQUENCY = 44100;

	private static final int SEGMENT_SIZE = FREQUENCY / 52;

	private static final int CHANNEL_COUNT = 4;

	private Instr[] instrs;
	// only using 1, 2, 3, 5, 6, 7, 8, 10 and 14!!

	private ChannelConfig[] configs;

	private ChannelPlayer[] players;

	
	
	private Song song;


	
	
	
	
	public SampleStore getJingle(int number) {
		setUpSong("jingle");
		return generate(new JingleSongSlice(number));
	}
	
	public Loop getSong(String song) {
		SampleStore a = generate(new FirstBlockSongSlice());
		SampleStore b = generate(new LoopSongSlice());
		return new Loop(a, b);
	}

	public void setUpSong(String s) {
		loadSong(s);
	}
	
	public SampleStore generate(SongSlice bn) {
		return generate(bn.isContinuing(), bn.first(), bn.last(), bn.leadOut());
	}

	public SampleStore generate(boolean isContinuing, int first, int last, boolean giveLeadOut) {
		if (!isContinuing) {
			generatePlayers();
		}
		byte[] sequence = song.getSequence();

		ArrayList<Integer> blockNumbers = new ArrayList<Integer>();
		
		first = Math2.limit(0, sequence.length, first);
		last = Math2.limit(0, sequence.length, last);
		for (int b=first; b<last; b++) {
			blockNumbers.add((int) sequence[b]);
		}

		int leadOut = giveLeadOut ? 64 : 0;
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

	void loadSong(String s) {
		song = new Song(new DataSrc(OpenableTools.mustLoad(TTResource.sound(s+ ".song"))));
	}

	private void generatePlayers() {
		players = new ChannelPlayer[CHANNEL_COUNT];
		assert configs.length == CHANNEL_COUNT;
		for (int x = 0; x < CHANNEL_COUNT; x++) {
			players[x] = new ChannelPlayer(this, configs[x]);
		}
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
		//
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

	private void generateConfigs() {
		configs = new ChannelConfig[] { new ChannelConfig(0.25f, true), // 0
				new ChannelConfig(0.75f, true), // 1
				new ChannelConfig(0.75f, true), // 2
				new ChannelConfig(0.25f, true), // 3
		};
	}


	public MusicPlayer() {
		loadInstruments();
		generateConfigs();
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

