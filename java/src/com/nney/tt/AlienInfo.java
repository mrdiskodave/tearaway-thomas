package com.nney.tt;

import com.nney.tt.aliens.Alien;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sprites.AnimsPool;

public class AlienInfo {
	public final int typeCode;
	private final String baseName;
	public final Class<? extends Alien> alienClass;
	public final int score;
	private String animsName;

	public String animsName() {
		return animsName;
	}

	AlienInfo(int id, String baseName, int score, Class<? extends Alien> alienClass) {
		this.typeCode = id;
		this.baseName = baseName;
		this.score = score;
		this.alienClass = alienClass;
	}

	AlienInfo(int id, String animsName, Class<? extends Alien> alienClass) {
		this(id, animsName, -1, alienClass);
	}

	Alien instantiate() {
		try {
			Alien answer = alienClass.newInstance();
			answer.alienInfo = this;
			return answer;
		}
		catch (InstantiationException e) {
			System.out.println(animsName);
			throw new RuntimeException(e);
		}
		catch (IllegalAccessException e) {
			System.out.println(animsName);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Set this object into the named world.
	 * 
	 * @param worldName
	 * @return Did we find graphics in that world? <code>true</code> meaning
	 *         that we did or <code>false</code> meaning that we did not.
	 */
	public boolean setWorld(String worldName) {
		animsName = baseName;
		if (animsName == null) return true;
		if (baseName.charAt(0) == '?') {
			String rest = baseName.substring(1);
			animsName = worldName + rest;
			if (TTResource.spriteExists(animsName)) return true;
			animsName = '0' + rest;
			return TTResource.spriteExists(animsName);
		}
		// just assume it exists!
		return true; 
	}

	public void connectAnims(Alien alien, AnimsPool animsPool) {
		if (animsName != null) {
			alien.connectAnims(animsPool.expect(animsName));
		}
	}
}
