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

	private String getName() {
		return field.getName();
	}

	public String label() {
		String answer = getAnn().label();
		if (answer.length() == 0) answer = getName();
		return answer;
	}

	public String name() {
		String answer = getAnn().name();
		if (answer.length() == 0) answer = humaniseIdentifier(label());
		return answer;
	}

	/**
	 * Transform the given string a Java identifier to something more human readable.
	 * e.g. from "aJavaIdentifier" to "A Java Identifier".
	 * 
	 * @param s The java identifier.
	 * @return The human readable.
	 */
	private static String humaniseIdentifier(String s) {
		StringBuffer b = new StringBuffer();
		b.append(s.substring(0, 1).toUpperCase());
		for (int x = 1; x < s.length(); x++) {
			char c = s.charAt(x);
			if (Character.getType(c) == Character.UPPERCASE_LETTER) {
				b.append(' ');
			}
			b.append(c);
		}
		return b.toString();
	}
}
