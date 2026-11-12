package com.nxdump

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import com.nxdump.core.Dumper
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.util.HashMap
import java.util.concurrent.ConcurrentHashMap

class SafSink(ctx: Context, private val tree: Uri, wantedName: String) : Dumper.Sink {
    private val resolver = ctx.contentResolver
    private val dirs = HashMap<String, Uri>()
    private val nativeDirs = ConcurrentHashMap<String, File>()
    val topName: String
    private val nativeBaseDir: File?

    init {
        var name = wantedName
        val treeId = try { DocumentsContract.getTreeDocumentId(tree) ?: "" } catch (_: Exception) { "" }
        val hasAllFilesAccess = Build.VERSION.SDK_INT < Build.VERSION_CODES.R || Environment.isExternalStorageManager()

        val parsedDir: File? = when {
            treeId.startsWith("raw:") -> File(treeId.removePrefix("raw:"))
            treeId.startsWith("primary:") -> {
                val sub = treeId.removePrefix("primary:").trim('/')
                if (sub.isEmpty()) Environment.getExternalStorageDirectory()
                else File(Environment.getExternalStorageDirectory(), sub)
            }
            treeId == "downloads" || treeId.startsWith("msd:") || treeId.startsWith("msf:") -> {
                File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "NxDump")
            }
            treeId.contains(":") -> {
                val parts = treeId.split(":", limit = 2)
                val vol = File("/storage", parts[0])
                if (vol.exists()) {
                    val sub = parts[1].trim('/')
                    if (sub.isEmpty()) vol else File(vol, sub)
                } else null
            }
            else -> null
        }

        val candidateDir: File? = if (parsedDir != null && (parsedDir.exists() || parsedDir.mkdirs()) && parsedDir.canWrite()) {
            parsedDir
        } else if (hasAllFilesAccess) {
            val fallback = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "NxDump")
            fallback.mkdirs()
            if (fallback.canWrite()) fallback else null
        } else {
            null
        }

        if (candidateDir != null) {
            var target = File(candidateDir, name)
            var n = 2
            while (target.exists()) {
                name = "$wantedName ($n)"
                target = File(candidateDir, name)
                n++
            }
            if (!target.mkdirs() && !target.exists()) {
                throw IOException("Cannot create output directory: ${target.absolutePath}")
            }
            try { File(target, ".nomedia").createNewFile() } catch (_: Exception) {}
            nativeBaseDir = target
            nativeDirs[""] = target
            
            // Pre-create common RomFS directory structures to eliminate FUSE syscall latency during parallel writes
            val commonSubdirs = arrayOf(
                "romfs", "romfs/Actor", "romfs/Camera", "romfs/Event", "romfs/Layout", 
                "romfs/Map", "romfs/Model", "romfs/Pack", "romfs/Physics", "romfs/Resource", 
                "romfs/System", "romfs/Terrain", "romfs/UI", "romfs/Voice", "exefs"
            )
            for (sub in commonSubdirs) {
                val d = File(target, sub)
                d.mkdirs()
                nativeDirs[sub] = d
            }
            
            topName = "[NATIVE-FAST] ${target.absolutePath}"
        } else {
            nativeBaseDir = null
            val root = DocumentsContract.buildDocumentUriUsingTree(tree, treeId)
            var n = 2
            while (findChild(root, name) != null) name = "$wantedName ($n)".also { n++ }
            topName = "[SAF-SLOW] $name"
            dirs[""] = createSafDoc(root, DocumentsContract.Document.MIME_TYPE_DIR, name)
        }
    }

    private fun findChild(parent: Uri, name: String): Uri? {
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getDocumentId(parent))
        resolver.query(
            children,
            arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME),
            null, null, null,
        )?.use { c ->
            while (c.moveToNext()) {
                if (c.getString(1) == name) return DocumentsContract.buildDocumentUriUsingTree(tree, c.getString(0))
            }
        }
        return null
    }

    private fun createSafDoc(parent: Uri, mime: String, name: String): Uri =
        DocumentsContract.createDocument(resolver, parent, mime, name)
            ?: throw IOException("Cannot create \"$name\" in the output folder")

    @Synchronized
    private fun safDir(path: String): Uri {
        dirs[path]?.let { return it }
        val parent = safDir(path.substringBeforeLast('/', ""))
        val name = path.substringAfterLast('/')
        val u = createSafDoc(parent, DocumentsContract.Document.MIME_TYPE_DIR, name)
        dirs[path] = u
        return u
    }

    private fun nativeDir(path: String): File {
        nativeDirs[path]?.let { return it }
        val base = nativeBaseDir ?: throw IOException("Native base missing")
        val d = File(base, path)
        if (!d.exists()) {
            synchronized(this) {
                if (!d.exists()) d.mkdirs()
            }
        }
        nativeDirs[path] = d
        return d
    }

    override fun open(relativePath: String): OutputStream {
        val subDir = relativePath.substringBeforeLast('/', "")
        val fileName = relativePath.substringAfterLast('/')

        return if (nativeBaseDir != null) {
            val dir = nativeDir(subDir)
            FileOutputStream(File(dir, fileName))
        } else {
            val d = safDir(subDir)
            val f = createSafDoc(d, "application/octet-stream", fileName)
            val os = resolver.openOutputStream(f, "w") ?: throw IOException("Cannot write $relativePath")
            BufferedOutputStream(os, 256 * 1024)
        }
    }
}
