package com.nney.datanode;

public interface WideDataDestination {
	void beginArray();

	void endArray();

	void beginObject();

	void endObject();

	void writeKey(String value);

	void write(double value);

	void write(int value);

	void write(long value);

	void write(boolean value);

	void write(String value);

	void writeNull();
}
