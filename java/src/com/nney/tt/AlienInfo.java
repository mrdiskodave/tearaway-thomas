package com.nney.tt;

import com.nney.tt.aliens.Alien;
import com.nney.tt.sprites.AnimsPool;

public class AlienInfo {
	public final int typeCode;
	private final String baseName;
	private String animsName;
	public final Class<? extends Alien> alienClass;
	public final int score;

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

	public void setWorld(String worldName) {
		animsName = baseName;
		if (baseName != null && baseName.charAt(0) == '?') {
			animsName = worldName + baseName.substring(1);
		}
	}

	public void connectAnims(Alien alien, AnimsPool animsPool) {
		if (animsName != null) {
			alien.connectAnims(animsPool.expect(animsName));
		}
	}
}
