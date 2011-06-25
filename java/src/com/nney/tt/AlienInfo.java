package com.nney.tt;

import com.nney.tt.aliens.Alien;

public class AlienInfo {
	public final int typeCode;
	public final String animsName;
	public final Class<? extends Alien> alienClass;
	public final int score;

	AlienInfo(int id, String animsName, int score, Class<? extends Alien> alienClass) {
		this.typeCode = id;
		this.animsName = animsName;
		this.score = score;
		this.alienClass = alienClass;
	}

	AlienInfo(int id, String animsName, Class<? extends Alien> alienClass) {
		this(id, animsName, -1, alienClass);
	}

	Alien instantiate() {
		try {
			return alienClass.newInstance();
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
}
