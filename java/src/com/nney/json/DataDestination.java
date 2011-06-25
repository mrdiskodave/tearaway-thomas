package com.nney.json;

public interface DataDestination {
	void beginArray();
	
	void beginDict();
	
	void end();
	
 	void write(double value); 

	void write(int value);

	void write(long value);

	void write(boolean value);

	void write(String value);
	
	void writeNull();
}
