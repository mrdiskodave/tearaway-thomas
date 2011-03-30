package com.nney.json;

/**
 * An interface for serialising objects.
 * 
 * There are basic types (double int long String boolean null). There are lists and maps.
 * List contain elements. Maps contained named fields.
 * 
 * The serialisation strategy is this:
 * Lists are used for serialising sequences.
 * Maps are used for seralising objects (with field names being the java object's field names).
 * This should be all you need to serialise your Java objects.
 * 
 * Attempts to do more concise or neat things should generally be avoided.
 * e.g. "my complex data structure can probably be serialised directly as a map (though I might need to also
 * include a list elsewhere to describe object order)"
 * I recommend you don't go there.
 * 
 * How to encode discriminated types:
 * i.e. when you are writing an object which could be an X or a Y how do you describe it and such the reader knows how to recognise it on reading?
 * The answer is to use a "typed structure" which is simply a Map following this conventional structure:  
 * { type: NAME_OF_TYPE, value: MAP_REPRESENTING_THE_OBJECT } 
 */
public interface DataWriter {
	void writeValue(double value);
	void writeValue(int value);
	void writeValue(long value);
	void writeValue(String value);
	void writeValue(boolean value);
	void writeNull();
	
	void beginList();
	
	void beginMap();

	void writeFieldName(String name);
	void end();
}
