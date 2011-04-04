package com.nney.utils;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

public class ClassResourceOpenable implements Openable {
	private final Class base;
	private final String name;

	public ClassResourceOpenable(Class base, String name) {
		this.base = base;
		this.name = name;
	}

	@Override
	public InputStream open() throws IOException {
		InputStream answer = base.getResourceAsStream(name);
		if (answer==null) {
			throw new FileNotFoundException(base.toString()+" "+name+" classpath resource not found");
		}
		return answer;
	}

}
