package com.nney.tt.sounds;

import junit.framework.TestCase;

import com.nney.tt.sounds.music.MusicPlayer;

public class AudioHubTest extends TestCase {
	public void testName() throws Exception {
		MusicPlayer mp = new MusicPlayer();
		MusicPlayerConnector mpc = new MusicPlayerConnector(mp);
		String song = "intro";
		Loop loop = mpc.getSong(song);
		// mp.setUpSong(song);
		// Sound a = new Sound(mp.generate(new
		// MusicPlayer.FirstBlockSlice()).collect());
		// Sound b = new Sound(mp.generate(new
		// MusicPlayer.LoopSlice()).collect());

		// assertions on?
	}
}
