package com.nney.tt;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienWithLocation;
import com.nney.tt.aliens.LegacyAlien;

public class AlienFactory {
	final private AlienInfoMap alienInfoMap;

	public AlienFactory(AlienInfoMap alienInfoMap) {
		this.alienInfoMap = alienInfoMap;
	}

	public void selectWorld(String name) {
		alienInfoMap.setWorld(name);
	}

	public Alien make(int typeCode, int x, int y, byte[] rest) {
		String tcName = AlienInfoMap.typeCodeToName(typeCode);
		Alien alien;
		if (alienInfoMap.nameExists(tcName)) {
			alien = alienInfoMap.getByName(tcName).instantiateAttach();
		}
		else {
			System.out.println("LEGACY ALIEN " + typeCode);
			alien = new LegacyAlien();
			alienInfoMap.attach(alien);
		}
		if (alien instanceof AlienWithLocation) {
			AlienWithLocation awl = (AlienWithLocation) alien;
			awl.c.x = x;
			awl.c.y = y;
		}
		alien.legacyData = rest;
		alien.loadFromLegacyData();
		return alien;
	}

	public Alien make(String name) {
		return alienInfoMap.getByName(name).instantiateAttach();
	}

	public void wrapExisting(Alien alien) {
		alienInfoMap.attach(alien);
	}
}
