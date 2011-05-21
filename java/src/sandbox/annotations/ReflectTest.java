package sandbox.annotations;

import java.lang.reflect.Field;

import junit.framework.TestCase;

public class ReflectTest extends TestCase {
	public class A {
		public int b;
		public int c;
	}
	
	public void test() throws Exception {
		A a = new A();
		Object o = a;
		Class<?> c = o.getClass();
		System.out.println(c.getCanonicalName());
		for (Field f: A.class.getFields()) {
			System.out.println(f.getName());
			
		}
		
		
	}

}
