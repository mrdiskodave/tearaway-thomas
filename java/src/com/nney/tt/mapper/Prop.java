package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;

public class Prop {
	protected AlienProp prop;
	
	public Prop(AlienProp prop) {
		this.prop = prop;
	}
	
	public String name() {
		return prop.name();
	}
	
	public String doc() {
		return prop.doc();
	}
}
