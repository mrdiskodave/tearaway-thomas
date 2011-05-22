package com.nney.tt;

import javax.management.RuntimeErrorException;

import com.nney.tt.aliens.Alien;

public class AlienInfo {
	public final int typeCode;
	public final String animsName;
	public final Class<? extends Alien> alienClass;

	AlienInfo(int id, String animsName, Class<? extends Alien> alienClass) {
		this.typeCode = id;
		this.animsName = animsName;
		this.alienClass = alienClass;
	}

	Alien instantiate() {
		try {
			return alienClass.newInstance();
		}
		catch (InstantiationException e) {
			throw new RuntimeException(e);
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}
}
