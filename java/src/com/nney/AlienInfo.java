package com.nney;

import com.nney.tt.aliens.Alien;

public class AlienInfo {
	public final int id;
	public final String spriteSetName;
	public final Class<? extends Alien> alienClass;

	AlienInfo(int id, String spriteSetName, Class<? extends Alien> alienClass) {
		this.id = id;
		this.spriteSetName = spriteSetName;
		this.alienClass = alienClass;
	}
	
	Alien ins() throws InstantiationException, IllegalAccessException {
		return alienClass.newInstance();
	}
}
