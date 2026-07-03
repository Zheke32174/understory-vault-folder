package com.understory.vaultfolder

import android.app.Service
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import android.os.ParcelFileDescriptor
import java.io.ByteArrayOutputStream
import java.io.DataInputStream

/**
 * Isolated-process renderer (§5.2). Runs with `android:isolatedProcess="true"`
 * and `android:exported="false"` — no permissions, no Keystore access, no
 * filesystem, no network. It receives the vault's DECRYPTED plaintext bytes over
 * an in-memory pipe (never a file on disk), decodes the hostile image/PDF in
 * this sandbox, and hands back an already-safe rendered bitmap (as PNG bytes
 * over a second in-memory pipe) to the vault process. A malformed-image or
 * malformed-PDF parser bug therefore executes where it cannot reach the KEK, the
 * blobs, or (the app has no INTERNET) the network.
 *
 * Protocol (Messenger): the client sends [MSG_RENDER] with:
 *   - `replyTo` = a Messenger to receive the reply.
 *   - `data` Bundle: [KEY_KIND] Int (KIND_IMAGE / KIND_PDF), [KEY_LEN] Int
 *     (plaintext length), [KEY_MAX_DIM] Int (viewport cap), and [KEY_IN_PFD] =
 *     a read-end [ParcelFileDescriptor] carrying exactly [KEY_LEN] bytes of
 *     plaintext. The FD travels in the Bundle (Messenger only marshals `data`
 *     across processes, never `obj`).
 * The reply is [MSG_RESULT] with either [KEY_PFD] (a read-end PFD of PNG-encoded
 * rendered pixels) on success or [KEY_ERROR] (a String) on failure.
 *
 * Text is NOT rendered here — it is inert and displayed directly in the vault
 * process (§5.3).
 */
class ViewerRenderService : Service() {

    private lateinit var worker: HandlerThread
    private lateinit var messenger: Messenger

    override fun onCreate() {
        super.onCreate()
        worker = HandlerThread("viewer-render").also { it.start() }
        messenger = Messenger(RenderHandler(worker.looper))
    }

    override fun onBind(intent: Intent?): IBinder = messenger.binder

    override fun onDestroy() {
        super.onDestroy()
        worker.quitSafely()
    }

    private class RenderHandler(looper: android.os.Looper) : Handler(looper) {
        override fun handleMessage(msg: Message) {
            if (msg.what != MSG_RENDER) { super.handleMessage(msg); return }
            val reply = msg.replyTo
            val data = msg.data
            @Suppress("DEPRECATION")
            val inPfd = data.getParcelable<ParcelFileDescriptor>(KEY_IN_PFD)
            val out = Message.obtain(null, MSG_RESULT)
            val bundle = Bundle()
            try {
                requireNotNull(inPfd) { "no input descriptor" }
                val kind = data.getInt(KEY_KIND)
                val len = data.getInt(KEY_LEN)
                val maxDim = data.getInt(KEY_MAX_DIM, 2048).coerceIn(256, 4096)
                val bytes = readExactly(inPfd, len)
                val bitmap = when (kind) {
                    KIND_IMAGE -> decodeImage(bytes, maxDim)
                    KIND_PDF -> renderPdfFirstPage(bytes, maxDim)
                    else -> null
                } ?: error("decode produced no image")
                val pfd = pngToPipe(bitmap)
                bitmap.recycle()
                bundle.putParcelable(KEY_PFD, pfd)
            } catch (t: Throwable) {
                bundle.putString(KEY_ERROR, t.message ?: t.javaClass.simpleName)
            } finally {
                runCatching { inPfd?.close() }
            }
            out.data = bundle
            runCatching { reply?.send(out) }
        }
    }

    companion object {
        const val MSG_RENDER = 1
        const val MSG_RESULT = 2

        const val KEY_KIND = "kind"
        const val KEY_LEN = "len"
        const val KEY_MAX_DIM = "maxDim"
        const val KEY_IN_PFD = "inPfd"
        const val KEY_PFD = "pfd"
        const val KEY_ERROR = "error"

        const val KIND_IMAGE = 1
        const val KIND_PDF = 2

        private fun readExactly(pfd: ParcelFileDescriptor, len: Int): ByteArray {
            ParcelFileDescriptor.AutoCloseInputStream(pfd).use { raw ->
                val dis = DataInputStream(raw)
                val buf = ByteArray(len)
                dis.readFully(buf)
                return buf
            }
        }

        /**
         * Decode an image from bytes only (never `decodeFile`), with an
         * inJustDecodeBounds pre-pass + downsample so a decompression bomb
         * can't OOM the sandbox.
         */
        private fun decodeImage(bytes: ByteArray, maxDim: Int): Bitmap? {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
            var sample = 1
            var w = bounds.outWidth
            var h = bounds.outHeight
            while ((w / sample) > maxDim || (h / sample) > maxDim) sample *= 2
            val opts = BitmapFactory.Options().apply { inSampleSize = sample }
            return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)
        }

        /**
         * Rasterize the first PDF page to a bitmap. [PdfRenderer] needs a
         * [ParcelFileDescriptor]; we supply an in-memory one built from the
         * bytes, not a temp file.
         */
        private fun renderPdfFirstPage(bytes: ByteArray, maxDim: Int): Bitmap? {
            val pfd = bytesToSeekablePfd(bytes)
            PdfRenderer(pfd).use { renderer ->
                if (renderer.pageCount == 0) return null
                renderer.openPage(0).use { page ->
                    val scale = maxDim.toFloat() / maxOf(page.width, page.height).coerceAtLeast(1)
                    val w = (page.width * scale).toInt().coerceAtLeast(1)
                    val h = (page.height * scale).toInt().coerceAtLeast(1)
                    val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
                    bmp.eraseColor(Color.WHITE)
                    page.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                    return bmp
                }
            }
        }

        /**
         * PdfRenderer requires a seekable FD. A pipe is not seekable, so back
         * the bytes with an ashmem region via [MemoryFile] and hand out its FD.
         */
        private fun bytesToSeekablePfd(bytes: ByteArray): ParcelFileDescriptor {
            val mf = android.os.MemoryFile("viewer-pdf", bytes.size)
            mf.writeBytes(bytes, 0, 0, bytes.size)
            // getFileDescriptor via reflection is required pre-API-33-safe path;
            // ashmem-backed MemoryFile exposes it. dup into a PFD the renderer owns.
            val getFd = android.os.MemoryFile::class.java.getDeclaredMethod("getFileDescriptor")
            getFd.isAccessible = true
            val fd = getFd.invoke(mf) as java.io.FileDescriptor
            return ParcelFileDescriptor.dup(fd)
        }

        /** Encode [bitmap] to PNG and stream it out through an in-memory pipe. */
        private fun pngToPipe(bitmap: Bitmap): ParcelFileDescriptor {
            val baos = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, baos)
            val png = baos.toByteArray()
            val pipe = ParcelFileDescriptor.createPipe()
            val readEnd = pipe[0]
            val writeEnd = pipe[1]
            Thread {
                ParcelFileDescriptor.AutoCloseOutputStream(writeEnd).use { it.write(png) }
            }.start()
            return readEnd
        }
    }
}
