package com.nney.tt.sounds;

import com.nney.tt.sounds.music.MusicPlayer;

/**
 * {@link MusicPlayer} has a broader interface than we need. This narrows class
 * it down to the one method. It does this by hiding extra features (e.g.
 * slicing modes) and TODOs (things that need tidying up like so-called
 * "jingles").
 */
public class MusicPlayerConnector {
	private final MusicPlayer mp;

	public MusicPlayerConnector(MusicPlayer mp) {
		this.mp = mp;
	}

	public Loop getSong(String song) {
		if (song.equals("gameover")) {
			return jing(0);
		}
		if (song.equals("startworld")) {
			return jing(1);
		}
		if (song.equals("levelcomplete")) {
			return jing(2);
		}
		if (song.equals("levelbegin")) {
			return jing(3);
		}
		mp.setUpSong(song);
		Sound a = mp.generate(new MusicPlayer.FirstBlockSlice());
		Sound b = mp.generate(new MusicPlayer.LoopSlice());
		return new Loop(a, b);
	}

	private Loop jing(int number) {
		mp.setUpSong("jingle");
		Sound a = mp.generate(new MusicPlayer.JingleSlice(number));
		return new Loop(a, null);
	}
}
