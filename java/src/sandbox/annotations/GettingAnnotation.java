package sandbox.annotations;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienProp;
import com.nney.tt.aliens.PurpleGemAlien;

@HelloAnno(value = "Hello", greetTo = "Universe")
public class GettingAnnotation {
	public static void main(String[] args) {
		
		
		
		
		Class<PurpleGemAlien> a = PurpleGemAlien.class;
		
		Field[] fs = a.getFields();
		for (Field f : fs) {
			AlienProp z = f.getAnnotation(AlienProp.class);
			if (z!=null) {
				Class<?> t = f.getType();
				System.out.println(t+" => "+f.getName()+" : "+z.xtraDef()+" "+z.name());
			}
		}
	}
}

//
// Class c = GettingAnnotation.class;
// Annotation[] annotations = c.getAnnotations();
// for (Annotation anno : annotations) {
// System.out.println("Annotation Type: " + anno.annotationType());
// }
//
// HelloAnno anno = (HelloAnno) c.getAnnotation(HelloAnno.class);
// System.out.println("Anno Value  : " + anno.value());
// System.out.println("Anno GreetTo: " + anno.greetTo());
//
// try {
// Method m = c.getMethod("sayHi");
//
// anno = m.getAnnotation(HelloAnno.class);
// System.out.println("Anno Value  : " + anno.value());
// System.out.println("Anno GreetTo: " + anno.greetTo());
// } catch (NoSuchMethodException e) {
// e.printStackTrace();
// }
//
// demo.sayHello();
// }
//
// @HelloAnno(value = "Hi", greetTo = "Alice")
// public void sayHi() {
// }
//
// @HelloAnno(value = "Hello", greetTo = "Bob")
// public void sayHello() {
// try {
// Method m = getClass().getMethod("sayHello");
// HelloAnno anno = m.getAnnotation(HelloAnno.class);
//
// System.out.println(anno.value() + " " + anno.greetTo());
// } catch (NoSuchMethodException e) {
// e.printStackTrace();
// }
// }
