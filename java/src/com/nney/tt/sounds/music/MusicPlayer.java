package com.nney.tt.sounds.music;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.resources.TTResource;
import com.nney.tt.sounds.Sound;
import com.nney.utils.Math2;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class MusicPlayer {
	static abstract class Slice {
		void getRunningOrder(List<Integer> destination, int length) {
			for (int x=0; x<length; x++) {
				destination.add(x);
			}
		}

		boolean isContinuing() {
			return false;
		}
	}

	class EntireSlice extends Slice {
	}

	public static class FirstBlockSlice extends Slice {
		@Override
		void getRunningOrder(List<Integer> destination, int length) {
			destination.add(0);
		}
	}

	public static class LoopSlice extends Slice {
		@Override
		void getRunningOrder(List<Integer> destination, int length) {
			// all blocks after the first block then the first block again
			for (int x=1; x<length; x++) {
				destination.add(x);
			}
			destination.add(0);
		}	
			
		@Override
		boolean isContinuing() {
			// we're continuing from the first block
			return true;
		}
	}

	public static class JingleSlice extends Slice {
		private final int number;

		public JingleSlice(int number) {
			this.number = number;
		}

		@Override
		void getRunningOrder(List<Integer> destination, int length) {
			destination.add(number);
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
	
	public void setUpSong(String s) {
		song = new Song(new DataSrc(OpenableTools.mustLoad(TTResource.music(s+ ".song"))));
	}
	
	public Sound generate(Slice bn) {
		if (!bn.isContinuing()) {
			generatePlayers();
		}
		byte[] sequence = song.getSequence();

		ArrayList<Integer> order = new ArrayList<Integer>();
		bn.getRunningOrder(order, sequence.length);
		
		int steps = 0;
		for (int b = 0; b < order.size(); b++) {
			steps += new Block(song, sequence[order.get(b)]).lines;
		}
		int clickLength = song.clickLength();
		steps *= clickLength;
		steps *= SEGMENT_SIZE;

		SampleStore sampleStore = new SampleStore(steps);

		for (int b = 0; b < order.size(); b++) {
			Block block = new Block(song, sequence[order.get(b)]);
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

		sampleStore.dumpRange();

		return new Sound(sampleStore.collect(), FREQUENCY);
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
		byte[][] sample = new byte[3][];
		for (int s = 0; s < sample.length; s++) {
			Openable sampleOpenable = TTResource.music(String.format("samp%s.bin", s + 1));
			sample[s] = OpenableTools.mustLoad(sampleOpenable);
		}

		//
		// load the instruments
		//
		DataSrc iblk = new DataSrc(OpenableTools.mustLoad(TTResource.music("iblk")));
		instrs = new Instr[16];
		for (int x = 0; x < 16; x++) {
			instrs[x] = new Instr(iblk.subDataSrc(x * 94, 94));
		}

		//
		// bind the samples
		//
		for (Instr i : instrs) {
			i.bind(sample);
			// 4: head bounce
			// 5: clang
			// 6: teleport
			// 7: worm
			// 8: trampaleen
			// 9: tink!
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

