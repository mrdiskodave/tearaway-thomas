package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;

public abstract class Prop {
	protected AlienProp aprop;
	
	public Prop(AlienProp aprop) {
		this.aprop = aprop;
	}
	
	public String name() {
		return aprop.name();
	}
	
	public String doc() {
		return aprop.doc();
	}
	
	abstract public String text();

}
