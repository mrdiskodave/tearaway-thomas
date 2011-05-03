package com.nney.tt;

import com.nney.tt.aliens.Alien;

public class AlienInfo {
	public final int id;
	public final String animsName;
	public final Class<? extends Alien> alienClass;

	AlienInfo(int id, String animsName, Class<? extends Alien> alienClass) {
		this.id = id;
		this.animsName = animsName;
		this.alienClass = alienClass;
	}
	
	Alien instantiate() throws InstantiationException, IllegalAccessException {
		return alienClass.newInstance();
	}
}
