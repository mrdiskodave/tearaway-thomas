package com.nney.tt.props;

import java.lang.reflect.Field;

import com.nney.tt.mapper.FieldAccessor;
import com.nney.tt.mapper.FieldAccessorImpl;

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

	public PropAnn getAnn() { 
		return field.getAnnotation(PropAnn.class);
	}
}
