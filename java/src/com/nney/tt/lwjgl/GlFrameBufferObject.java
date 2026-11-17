package com.nney.tt.lwjgl;

import org.lwjgl.opengl.EXTFramebufferObject;
import org.lwjgl.opengl.GL11;

import com.nney.tt.gfx.Disposable;
import com.nney.utils.mbr.MustBeReleased;

/**
 * This object redirects GL rendering for its lifetime (i.e. from construction
 * until {@link #close()} is called). Rendering is redirected into the given
 * texture.
 */
public final class GlFrameBufferObject implements Disposable {
	private final MustBeReleased mbr = new MustBeReleased();
	private final int myFBOId;

	/**
	 * Redirect rendering to a texture until {@link #close()} is called.
	 * 
	 * @param t
	 *            The texture we wish to render into.
	 */
	public GlFrameBufferObject(GlTexture t) {
		int w = t.width();
		int h = t.height();

		myFBOId = GlTools.genBufferName();
		t.attachToFBO(myFBOId);

		GL11.glPushAttrib(GL11.GL_VIEWPORT_BIT);
		GL11.glViewport(0, 0, w, h);

		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glPushMatrix();
		GL11.glLoadIdentity();
		GL11.glOrtho(0, w, 0, h, 1, -1);
	}

	@Override
	public void close() {
		GL11.glPopMatrix();
		GL11.glMatrixMode(GL11.GL_MODELVIEW);
		GL11.glPopAttrib();

		EXTFramebufferObject.glBindFramebufferEXT(EXTFramebufferObject.GL_FRAMEBUFFER_EXT, 0);
		EXTFramebufferObject.glDeleteFramebuffersEXT(myFBOId);
		mbr.release();
	}
}
