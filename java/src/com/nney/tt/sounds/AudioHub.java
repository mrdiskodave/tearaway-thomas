package com.nney.tt.sounds;

import java.util.HashMap;

import com.nney.json.DataItem;
import com.nney.tt.lwjgl.AlAudioContext;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sounds.music.MusicPlayer;
import com.nney.tt.sounds.wav.WavTools;
import com.nney.utils.OpenableTools;

public class AudioHub {
	private static final boolean SOUND_ENABLED = true;
	private MusicPlayerConnector mp = new MusicPlayerConnector(new MusicPlayer());
	private HashMap<String, Integer> fxMap = new HashMap<String, Integer>();
	private final AudioContext ac;
	private String[] slotContents = { "", "", "" };

	public AudioHub(AudioContext ac) {
		this.ac = ac;

		int indx = 0;
		for (DataItem i : TTResource.diFromText(TTResource.fx("def.txt")).requireList()) {
			String name = i.requireField("name").requireString();
			String data = i.requireField("data").requireString();
			
			byte[] d = OpenableTools.mustLoad(TTResource.fx(data));
			Sound sound = WavTools.read(d);
			
			float vol = (float) i.requireField("vol").requireDouble();
			if (i.fieldExists("freq")) {
				sound = new Sound(sound.data, i.requireField("freq").requireInt());
			}
			ac.loadEffect(vol, sound);
			fxMap.put(name, indx++);
		}
	}

	public void playEffect(String name) {
		if (SOUND_ENABLED) {
			Integer n = fxMap.get(name);
			if (n == null) throw new RuntimeException("Unknown sound effect: " + name);
			ac.playEffect(n);
		}
		else {
			System.out.println("SFX:" + name);
		}
	}
	
	public void loadMusic(int slot, String name) {
		if (name.equals(slotContents[slot])) return;
		ac.loadMusic(slot, renderMusic(name));
		slotContents[slot] = name;
	}

	public void startMusic(int slot) {
		if (SOUND_ENABLED) {
			ac.startMusic(slot);
		}
	}
	
	public void stopMusic() {
		ac.stopMusic();
	}
	

	private Loop renderMusic(String name) {
//		System.out.println("Rendering "+name);
		Loop loop = mp.getSong(name);
//		System.out.println("Done!");
		return loop;
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
		z.loadMusic(0, "intro");
		z.startMusic(0);
		for (;;) {
			pause();
			ac.update();
//			z.playEffect("tink");
		}
	}

}
