package com.nney.tt;

import com.nney.tt.aliens.Alien;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sprites.AnimsPool;

public class AlienInfo {
	public final int typeCode;
	public final String name;
	private final String animBaseName;
	public final int score;
	public final Class<? extends Alien> alienClass;
	
	private String animsName;

	public String animsName() {
		return animsName;
	}

	AlienInfo(int id, String name, String animBaseName, int score, Class<? extends Alien> alienClass) {
		this.typeCode = id;
		this.animBaseName = animBaseName;
		this.score = score;
		this.alienClass = alienClass;
		this.name = name;
	}

	AlienInfo(int id, String name, String animBaseName, Class<? extends Alien> alienClass) {
		this(id, name, animBaseName, -1, alienClass);
	}

	Alien instantiate() {
		try {
			Alien answer = alienClass.newInstance();
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
		animsName = animBaseName;
		if (animsName == null) return true;
		if (animBaseName.charAt(0) == '?') {
			String rest = animBaseName.substring(1);
			animsName = worldName + rest;
			if (TTResource.spriteExists(animsName)) return true;
			animsName = '0' + rest;
			return TTResource.spriteExists(animsName);
		}
		// just assume it exists!
		return true; 
	}

	static String makeInternalName(String s) {
		return "#"+s;
	}
	
	public boolean internal() {
		return name.charAt(0)=='#';
	}
}
