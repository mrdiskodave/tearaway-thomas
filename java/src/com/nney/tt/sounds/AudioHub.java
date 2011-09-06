package com.nney.tt.sounds;

import java.util.HashMap;

import com.nney.json.DataItem;
import com.nney.tt.lwjgl.AlAudioContext;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sounds.music.MusicPlayer;
import com.nney.utils.OpenableTools;

public class AudioHub {
	private static final int FREQ = 44100;
	private MusicPlayerConnector mp = new MusicPlayerConnector(new MusicPlayer());
	private HashMap<String, Integer> fxMap = new HashMap<String, Integer>();
	private final AudioContext ac;

	public AudioHub(AudioContext ac) {
		this.ac = ac;

		int indx = 0;
		for (DataItem i : TTResource.diFromText(TTResource.fx("def.txt")).requireList()) {
			String name = i.requireField("name").requireString();
			String data = i.requireField("data").requireString();
			byte[] d = OpenableTools.mustLoad(TTResource.fx(data));
			Sound sound = Sound.fromSam(d);
			float vol = (float) i.requireField("vol").requireDouble();
			int freq = i.requireField("freq").requireInt();
			ac.loadEffect(vol, freq, sound);
			fxMap.put(name, indx++);
			System.out.println("added");
		}
	}

	public void playEffect(String name) {
		Integer n = fxMap.get(name);
		if (n == null) throw new RuntimeException("Unknown sound effect: " + name);
		ac.playEffect(n);
	}

	public void startMusic(String name) {
		System.out.println("Rendering");
		Loop loop = mp.getSong(name);
		System.out.println("Done!");
		ac.startMusic(1f, FREQ, loop);
	}

	//
	// test routine
	//

	static private void pause() {
		try {
			Thread.sleep(100);
		}
		catch (InterruptedException e) {
			// ignored
		}
	}

	public static void main(String[] args) {
		AlAudioContext ac = new AlAudioContext();
		AudioHub z = new AudioHub(ac);
		z.startMusic("intro");
		for (;;) {
			pause();
			ac.update();
			z.playEffect("tink");
		}
	}
}
