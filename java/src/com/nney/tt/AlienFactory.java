package com.nney.tt;

import com.nney.tt.aliens.Alien;

public interface AlienFactory {
	Alien make(int typeCode);
}
