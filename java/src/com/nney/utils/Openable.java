package com.nney.utils;

import java.io.IOException;
import java.io.InputStream;

public interface Openable {
	InputStream open() throws IOException;
}
