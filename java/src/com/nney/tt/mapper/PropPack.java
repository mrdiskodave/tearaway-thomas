package com.nney.tt.mapper;

import java.lang.reflect.Field;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienProp;

public class PropPack {
	private final Alien alien;
	private final Field field;

	PropPack(Alien alien, Field field) {
		this.alien = alien;
		this.field = field;
	}

	public Alien alien() {
		return alien;
	}
	
	public FieldAccessor access() {
		return internalAccess();
	}

	private FieldAccessor internalAccess() {
		return new FieldAccessorImpl(alien, field);
	}

	public AlienProp getAnn() { 
		return field.getAnnotation(AlienProp.class);
	}
}
