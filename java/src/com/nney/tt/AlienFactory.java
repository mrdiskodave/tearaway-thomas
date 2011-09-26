package com.nney.tt;

import com.nney.tt.aliens.Alien;

public interface AlienFactory {
	void selectWorld(String name);
	Alien make(int typeCode);
}
