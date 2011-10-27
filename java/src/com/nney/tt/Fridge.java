package com.nney.tt;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.ListIterator;

import com.nney.utils.ReadOnlyIterator;

/**
 * A fridge is a one dimensional structure for freezing off-screen objects.
 * 
 * <ul>
 * <li>Objects in a fridge are known to be off-screen.
 * <li>Objects in a fridge do not consume any processing resources.
 * <li>Objects in a fridge need only a single small test (performed in
 * {@link #pop(int)}) that establishes if <b>any</b> of them are coming back
 * on screen (in a constant time ... not related to the number of objects).
 * </ul>
 * 
 * <p>
 * The caller needs to maintain a fridge per screen edge. i.e. four on a 2D screen
 * 
 * <p>
 * The fridge has a position system where objects with numerically larger
 * positions are deeper in the fridge (i.e. further off-screen). Objects with
 * smaller positions are closer to returning to the screen.
 * 
 * @param <T>
 *            The type of the object we hold.
 */
public class Fridge<T> implements Iterable<T> {
	private LinkedList<FridgeEntry> content = new LinkedList<FridgeEntry>();

	@SuppressWarnings("unused")
	// it's for debug output
	private String name;

	class FridgeEntry {
		final T item;
		final int pos;

		FridgeEntry(T item, int pos) {
			this.item = item;
			this.pos = pos;
		}
	}

	public Fridge(String name) {
		this.name = name;
	}

	/**
	 * Add an object to this fridge at the given position.
	 * 
	 * @param item
	 *            The object to add.
	 * @param pos
	 *            The place to put it.
	 */
	public void add(T item, int pos) {
		// System.out.println(String.format("Fridge: %08x(%7d) frozen    into %-6s",
		// item.hashCode(), pos, name));
		
		// Insert the item so the Fridge remains sorted by pos
		ListIterator<FridgeEntry> ci = content.listIterator();
		while (ci.hasNext()) {
			if (ci.next().pos >= pos) {
				ci.previous();
				break;
			}
		}
		// Insert it!
		ci.add(new FridgeEntry(item, pos));
	}

	/**
	 * Perhaps remove an object from this fridge.
	 * 
	 * @param edge
	 *            Only remove the object if it's position is less than this value
	 * @return The object, if removed, or <code>null</code>.
	 */
	public T pop(int edge) {
		FridgeEntry fe = content.peekFirst();
		if (fe == null || fe.pos > edge) return null;
		// System.out.println(String.format("Fridge: %08x(%7d) defrosted from %-6s using %d",
		// fe.item.hashCode(), fe.pos, name, edge));
		content.removeFirst();
		return fe.item;
	}

	@Override
	public Iterator<T> iterator() {
		final Iterator<FridgeEntry> it = content.iterator();
		return new ReadOnlyIterator<T>() {
			@Override
			public boolean hasNext() {
				return it.hasNext();
			}

			@Override
			public T next() {
				return it.next().item;
			}
		};
	}
}
