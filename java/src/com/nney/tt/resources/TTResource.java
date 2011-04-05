package com.nney.tt.resources;

import com.nney.utils.ClassResourceOpenable;

public class TTResource extends ClassResourceOpenable {
	private TTResource(String name) {
		super(TTResource.class, name);
	}
	
	public static TTResource plain(String name) {
		return new TTResource(name);
	}
	
	public static TTResource formatted(String format, Object... args) {
		return new TTResource(String.format(format, args));
	}
}
