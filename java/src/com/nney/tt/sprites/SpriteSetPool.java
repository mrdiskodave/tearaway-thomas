package com.nney.tt.sprites;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.TreeMap;

import com.nney.json.DataException;
import com.nney.json.DataItem;
import com.nney.json.JsonException;
import com.nney.json.JsonValue;
import com.nney.tt.resources.TTResource;
import com.nney.utils.StringIO;

public class SpriteSetPool {
	TreeMap<String, SpriteSet> pool = new TreeMap<String, SpriteSet>();
	
	public SpriteSet load(String spriteName) {
		SpriteSet answer = pool.get(spriteName);
		if (answer==null) {
			answer = populatePool(spriteName);
		}
		return answer;
	}

	private SpriteSet populatePool(String spriteName) {
		SpriteSet answer = loadSpriteSet(spriteName);
		pool.put(spriteName, answer);
		return answer;
	}
	
	private static SpriteSet loadSpriteSet(String spriteName) {
		
		ArrayList<Anim> an = new ArrayList<Anim>(); 
		HashMap<Integer, Sprite> cache = new HashMap<Integer, Sprite>();
		try {
			String text = StringIO.loadText(TTResource.spriteDef(spriteName), null);
			JsonValue diRoot = JsonValue.parse(text);
			
			for (DataItem diAnim : diRoot.requireField("anims").requireList()) {
				DataItem[] diFrames = diAnim.requireField("frames").requireList();
				Sprite[] frames = new Sprite[diFrames.length];
				for (int x=0; x<frames.length; x++) {
					int fno = diFrames[x].requireInt();
					Sprite frame = cache.get(fno);
					if (frame==null) {
						frame = LargeImageFrameLoader.load(TTResource.spriteFrame(spriteName, fno));
						cache.put(fno, frame);
					}
					else {
						System.out.println("**CACHE HIT**");
					}
					frames[x] = frame;
				}
				String name = null;
				if (diAnim.fieldExists("name")) {
					name = diAnim.requireField("name").requireString();
				}
				int rate = 0;
				if (diAnim.fieldExists("rate")) {
					rate = diAnim.requireField("rate").requireInt();
				}
				int repeatPos = -1;
				if (diAnim.fieldExists("repeatPos")) {
					repeatPos = diAnim.requireField("repeatPos").requireInt();
				}
				an.add(new Anim(rate, frames, repeatPos, name)); 
			}
			return new SpriteSet(an);
		}
		catch (JsonException e) {
			throw new RuntimeException(e);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		catch (DataException e) {
			throw new RuntimeException(e);
		}
	}

}
