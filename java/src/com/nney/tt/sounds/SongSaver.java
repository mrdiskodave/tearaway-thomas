package com.nney.tt.sounds;

import com.nney.tt.sounds.MusicPlayer.JingleSongSlice;
import com.nney.tt.sounds.MusicPlayer.LoopSongSlice;
import com.nney.tt.sounds.MusicPlayer.SongSlice;

public class SongSaver {
	private final MusicPlayer mp;
	private String songName;

	SongSaver(MusicPlayer mp) {
		this.mp = mp;
	}
	

	private void load(String s) {
		mp.setUpSong(s);
		songName = s;
	}

	private void saveSongSlice(SongSlice slice, String xtra) {
		String saveName = songName + xtra + ".wav";
		System.out.println("=== " + saveName);
		WaveWriter.saveWave(saveName, mp.generate(slice).collect(), MusicPlayer.FREQUENCY);
	}
	
	private void saveSong(String s) {
		load(s);
		// saveSongSlice(new EntireSongSlice(), "");
		saveSongSlice(new MusicPlayer.FirstBlockSongSlice(), "-begin");
		saveSongSlice(new LoopSongSlice(), "-loop");
	}

	private void execute() {
		saveSong("intro");
		saveSong("wood");
		saveSong("toy");
		saveSong("ice");
		saveSong("future");
		// saveSong("unused");

		// 0=game over 1=a new world 2=level complete 3=level begin

		load("jingle");
		saveSongSlice(new JingleSongSlice(0), "-gameover");
		saveSongSlice(new JingleSongSlice(1), "-startworld");
		saveSongSlice(new JingleSongSlice(2), "-levelcomplete");
		saveSongSlice(new JingleSongSlice(3), "-levelbegin");
	}
	
	public static void main(String[] args) {
		new SongSaver(new MusicPlayer()).execute();
	}
}
