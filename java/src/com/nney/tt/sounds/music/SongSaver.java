package com.nney.tt.sounds.music;

import com.nney.tt.sounds.music.MusicPlayer.JingleSlice;
import com.nney.tt.sounds.music.MusicPlayer.LoopSlice;
import com.nney.tt.sounds.music.MusicPlayer.Slice;
import com.nney.tt.sounds.wav.WaveWriter;

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

	private void saveSongSlice(Slice slice, String xtra) {
		String saveName = songName + xtra + ".wav";
		System.out.println("=== " + saveName);
		WaveWriter.saveWave(saveName, mp.generate(slice));
	}
	
	private void saveSong(String s) {
		load(s);
		// saveSongSlice(new EntireSongSlice(), "");
		saveSongSlice(new MusicPlayer.FirstBlockSlice(), "-begin");
		saveSongSlice(new LoopSlice(), "-loop");
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
		saveSongSlice(new JingleSlice(0), "-gameover");
		saveSongSlice(new JingleSlice(1), "-startworld");
		saveSongSlice(new JingleSlice(2), "-levelcomplete");
		saveSongSlice(new JingleSlice(3), "-levelbegin");
	}
	
	public static void main(String[] args) {
		new SongSaver(new MusicPlayer()).execute();
	}
}
