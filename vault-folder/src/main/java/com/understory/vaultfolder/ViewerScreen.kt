package com.understory.vaultfolder

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import android.os.ParcelFileDescriptor
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.understory.security.Crypto
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The mime kinds the viewer can render; anything else has no View affordance. */
internal object ViewerSupport {
    fun isImage(mime: String): Boolean = mime.startsWith("image/")
    fun isPdf(mime: String): Boolean = mime == "application/pdf"
    fun isText(mime: String): Boolean =
        mime == "text/plain" || mime == "text/csv" || mime == "application/json" ||
            mime.startsWith("text/")

    fun isSupported(mime: String): Boolean = isImage(mime) || isPdf(mime) || isText(mime)
}

private sealed interface ViewState {
    object Loading : ViewState
    data class ImageReady(val bitmap: Bitmap) : ViewState
    data class TextReady(val text: String) : ViewState
    data class Failed(val msg: String) : ViewState
}

/**
 * In-app, memory-only viewer (§5). Decrypts the blob to an in-memory
 * ByteArray in the VAULT process, then:
 *   - text is inert → decoded + shown directly here;
 *   - image/PDF → handed to the isolated [ViewerRenderService] over an in-memory
 *     pipe; the sandbox returns a rendered bitmap. No plaintext ever hits disk,
 *     no share-sheet, no decrypt-to-cache — the viewer is a terminal sink.
 *
 * The host window inherits FLAG_SECURE from MainActivity (single-activity app),
 * so screenshots / screen-record stay blocked.
 */
@Composable
fun ViewerScreen(
    store: VaultFolderStore,
    entry: VaultFolderEntry,
    onBack: () -> Unit,
) {
    val ctx = LocalContext.current
    var state by remember(entry.id) { mutableStateOf<ViewState>(ViewState.Loading) }

    DisposableEffect(entry.id) {
        val scope = CoroutineScope(Dispatchers.Main)
        val renderer = IsolatedRenderer(ctx.applicationContext)
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val plaintext = store.readBlobBytes(entry)
                    try {
                        when {
                            ViewerSupport.isText(entry.mimeType) ->
                                ViewState.TextReady(decodeText(plaintext))
                            ViewerSupport.isImage(entry.mimeType) ->
                                ViewState.ImageReady(renderer.render(plaintext, ViewerRenderService.KIND_IMAGE))
                            ViewerSupport.isPdf(entry.mimeType) ->
                                ViewState.ImageReady(renderer.render(plaintext, ViewerRenderService.KIND_PDF))
                            else -> ViewState.Failed("unsupported")
                        }
                    } finally {
                        // Wipe the plaintext the moment the bytes are handed off
                        // (§5.4 memory hygiene). The renderer already copied them
                        // across the pipe.
                        Crypto.wipe(plaintext)
                    }
                }.getOrElse { ViewState.Failed(it.message ?: it.javaClass.simpleName) }
            }
            state = result
        }
        onDispose {
            scope.cancel()
            renderer.close()
            (state as? ViewState.ImageReady)?.bitmap?.recycle()
        }
    }

    SuiteScaffold(
        title = entry.name,
        onBack = onBack,
        showSuiteFooter = false,
    ) { pad ->
        Box(
            modifier = Modifier.fillMaxSize().padding(pad),
            contentAlignment = Alignment.Center,
        ) {
            when (val s = state) {
                is ViewState.Loading -> Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
                ) {
                    CircularProgressIndicator()
                    Text(
                        stringResource(R.string.viewer_decoding),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                is ViewState.ImageReady -> Image(
                    bitmap = s.bitmap.asImageBitmap(),
                    contentDescription = entry.name,
                    modifier = Modifier.fillMaxSize().padding(UnderstoryTheme.spacing.sm),
                )
                is ViewState.TextReady -> Text(
                    s.text,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(UnderstoryTheme.spacing.lg),
                )
                is ViewState.Failed -> Text(
                    if (s.msg == "unsupported") stringResource(R.string.viewer_unsupported)
                    else stringResource(R.string.viewer_failed),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(UnderstoryTheme.spacing.lg),
                )
            }
        }
    }
}

/** Cap text preview so a giant file can't stall the UI thread on layout. */
private const val MAX_TEXT_CHARS = 200_000

private fun decodeText(bytes: ByteArray): String {
    val s = String(bytes, Charsets.UTF_8)
    return if (s.length > MAX_TEXT_CHARS) s.substring(0, MAX_TEXT_CHARS) + "\n…(truncated)" else s
}

/**
 * Binds the isolated [ViewerRenderService], ships plaintext over an in-memory
 * pipe, and blocks for the rendered bitmap. One-shot per viewer; closed on
 * dispose. All calls here run off the main thread (invoked from Dispatchers.IO).
 */
private class IsolatedRenderer(private val ctx: Context) {

    private var conn: ServiceConnection? = null
    @Volatile private var service: Messenger? = null
    private val replyThread = HandlerThread("viewer-reply").also { it.start() }

    fun render(plaintext: ByteArray, kind: Int): Bitmap {
        val svc = bindBlocking()
        val pipe = ParcelFileDescriptor.createPipe()
        val readEnd = pipe[0]
        val writeEnd = pipe[1]
        // Feed the plaintext to the service across the pipe on a side thread.
        Thread {
            ParcelFileDescriptor.AutoCloseOutputStream(writeEnd).use { it.write(plaintext) }
        }.start()

        var replyPfd: ParcelFileDescriptor? = null
        var errText: String? = null
        val done = Object()
        val replyMessenger = Messenger(object : Handler(replyThread.looper) {
            override fun handleMessage(msg: Message) {
                val b = msg.data
                @Suppress("DEPRECATION")
                replyPfd = b.getParcelable(ViewerRenderService.KEY_PFD)
                errText = b.getString(ViewerRenderService.KEY_ERROR)
                synchronized(done) { done.notifyAll() }
            }
        })

        val out = Message.obtain(null, ViewerRenderService.MSG_RENDER)
        out.replyTo = replyMessenger
        out.data = Bundle().apply {
            putInt(ViewerRenderService.KEY_KIND, kind)
            putInt(ViewerRenderService.KEY_LEN, plaintext.size)
            putInt(ViewerRenderService.KEY_MAX_DIM, 2048)
            putParcelable(ViewerRenderService.KEY_IN_PFD, readEnd)
        }
        synchronized(done) {
            svc.send(out)
            done.wait(15_000)
        }
        // The Bundle dup'd the FD for transport; close our local read end.
        runCatching { readEnd.close() }
        val pfd = replyPfd ?: error("render timed out or failed: ${errText ?: "no reply"}")
        try {
            val bytes = ParcelFileDescriptor.AutoCloseInputStream(pfd).use { it.readBytes() }
            return BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                ?: error("could not decode rendered image")
        } finally {
            runCatching { pfd.close() }
        }
    }

    private fun bindBlocking(): Messenger {
        service?.let { return it }
        val ready = Object()
        val c = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                synchronized(ready) {
                    service = binder?.let { Messenger(it) }
                    ready.notifyAll()
                }
            }
            override fun onServiceDisconnected(name: ComponentName?) {
                service = null
            }
        }
        conn = c
        val intent = Intent(ctx, ViewerRenderService::class.java)
        val bound = ctx.bindService(intent, c, Context.BIND_AUTO_CREATE)
        check(bound) { "could not bind viewer render service" }
        synchronized(ready) {
            if (service == null) ready.wait(10_000)
        }
        return service ?: error("viewer render service did not connect")
    }

    fun close() {
        conn?.let { runCatching { ctx.unbindService(it) } }
        conn = null
        service = null
        replyThread.quitSafely()
    }
}
