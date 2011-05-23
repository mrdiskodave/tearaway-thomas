package com.nney.tt.mapper;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class FieldAccessorImpl implements FieldAccessor {
	private final Field f;
	private final Object o;

	public FieldAccessorImpl(Object o, Field f) {
		this.f = f;
		this.o = o;
	}

	@Override
	public Object get() {
		try {
			return f.get(o);
		}
		// unrecoverable exceptions ...
		catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void put(Object v) {
		try {
			f.set(o, v);
		}
		// unrecoverable exceptions ...
		catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Object getCopy() {
		Object o = get();
		return cloneAnObject(o);
	}

	/**
	 * Clone and object.
	 * 
	 * <p>
	 * Wow, this is more tricky than it should be. You <a href=
	 * "http://weblogs.java.net/blog/2007/04/04/cloning-java-objects-using-serialization"
	 * >see</a>, if <code>x</code> is declared as an Object then you can't just
	 * call <code>x.clone()</code> because <code>Object.clone()</code> is
	 * protected. If <code>Cloneable</code> defined a public
	 * <code>clone()</code> method, then you could use
	 * <code>((Cloneable) x).clone()</code>. But it doesn't. So you either have
	 * to enumerate all the classes that you think <code>x</code> could be
	 * (which is horrid) or resort to reflection (which is what I've done here).
	 * 
	 * <p>
	 * A <a href=
	 * "http://stackoverflow.com/questions/1803503/why-are-java-enums-not-clonable"
	 * >further<a> gotcha is that immutable types cannot be cloned (and don't
	 * need to be) <b>but</b> there is no run-time way to ask if a type is
	 * immutable. I've included a list of the ones I'm using.
	 * 
	 * @param o
	 *            Object to clone.
	 * @return The cloned object.
	 */
	static private Object cloneAnObject(Object o) {
		if (o instanceof Boolean || o instanceof Enum || o instanceof String) {
			return o;
		}
		try {
			Method clone = o.getClass().getMethod("clone");
			return clone.invoke(o);
		}
		// unrecoverable exceptions ...
		catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
		catch (InvocationTargetException e) {
			throw new RuntimeException(e);
		}
		catch (SecurityException e) {
			throw new RuntimeException(e);
		}
		catch (NoSuchMethodException e) {
			// we COULD assume immutability here
			// but I'm not prepared to risk it
			// TODO: 70: yet?
			throw new RuntimeException(e);
		}
	}

	@Override
	public String toString() {
		return f.getName();
	}

	public String fieldName() {
		return f.getDeclaringClass().getCanonicalName()+" "+f.getName();
	}
}
