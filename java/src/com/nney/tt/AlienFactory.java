package com.nney.tt;

import com.nney.tt.aliens.Alien;

public interface AlienFactory {
	void selectWorld(String name);
	
	Alien make(int typeCode, int x, int y, byte[] rest);
	Alien make(String name);
	void wrapExisting(Alien alien);
}
