package com.nney.tt;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.ListIterator;

/**
 * A fridge is a one dimensional structure for freezing off-screen objects.
 * 
 * <ul>
 * <li>Objects in a fridge are known to be off-screen.
 * <li>Objects in a fridge do not consume any processing resources.
 * <li>Objects in a fridge need only a single small test (performed in
 * {@link #remove(int)}) that establishes if <b>any</b> of them are coming back
 * on screen (in a constant time ... not related to the number of objects).
 * </ul>
 * 
 * <p>
 * The caller needs to maintain a fridge per screen edge.
 * 
 * <p>
 * The fridge has a position system where objects with numerically larger
 * positions are deeper in the fridge (i.e. further off-screen). Objects with
 * smaller positions are closer to returning to the screen. This means that,
 * when a screen edge is encountered as the ordinate increases, fridge-position
 * is the same as screen ordinate. However, the fridge for the opposite screen
 * edges will need its given fridge-positions negated by the caller.
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
		// Skip (to the right) over existing items that should be to
		// the left of the one we've been given.
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
	 * @param left
	 *            Only remove the object if is left of (or on) this position.
	 * @return The object, if removed, or <code>null</code>.
	 */
	public T remove(int left) {
		FridgeEntry fe = content.peekFirst();
		if (fe == null || fe.pos > left) return null;
		// System.out.println(String.format("Fridge: %08x(%7d) defrosted from %-6s using %d",
		// fe.item.hashCode(), fe.pos, name, left));
		assert fe == content.removeFirst();
		return fe.item;
	}

	/**
	 * A slow method to delete an object from anywhere in the fridge. Not
	 * intended for real-time use.
	 * 
	 * @param t
	 *            The object to look for.
	 * @return <code>true</code> meaning "we found it and deleted it" or
	 *         <code>false</code> meaning "we didn't find it".
	 */
	public boolean delete(T t) {
		for (Iterator<FridgeEntry> i = content.iterator(); i.hasNext();) {
			FridgeEntry z = i.next();
			if (z.item == t) {
				i.remove();
				return true;
			}
		}
		return false;
	}

	public void clear() {
		content.clear();
	}

	@Override
	public Iterator<T> iterator() {
		final Iterator<FridgeEntry> it = content.iterator();
		return new Iterator<T>() {
			@Override
			public boolean hasNext() {
				return it.hasNext();
			}

			@Override
			public T next() {
				return it.next().item;
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException("Cannot remove elements from Fridge iterator");
			}
		};
	}
}
