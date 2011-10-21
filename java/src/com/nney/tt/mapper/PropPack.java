package com.nney.tt.mapper;

import java.lang.reflect.Field;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienProp;

/**
 * The things needed to initialise a {@link Prop}.
 */
public class PropPack {
	private final Object object;
	private final Field field;

	PropPack(Object object, Field field) {
		this.object = object;
		this.field = field;
	}

	public FieldAccessor access() {
		return internalAccess();
	}

	private FieldAccessor internalAccess() {
		return new FieldAccessorImpl(object, field);
	}

	public AlienProp getAnn() { 
		return field.getAnnotation(AlienProp.class);
	}
}
