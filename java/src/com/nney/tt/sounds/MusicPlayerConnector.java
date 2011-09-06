package com.nney.tt.sounds;

import com.nney.tt.sounds.music.MusicPlayer;

/**
 * {@link MusicPlayer} has a broader interface than we need. This narrows class
 * it down to the one method. It does this by hiding extra features (e.g.
 * slicing modes) and things that need tidying up (e.g. "jingles").
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
		Sound a = new Sound(mp.generate(new MusicPlayer.FirstBlockSlice()).collect());
		Sound b = new Sound(mp.generate(new MusicPlayer.LoopSlice()).collect());
		return new Loop(a, b);
	}

	private Loop jing(int number) {
		mp.setUpSong("jingle");
		Sound a = new Sound(mp.generate(new MusicPlayer.JingleSlice(number)).collect());
		return new Loop(a, null);
	}
}
