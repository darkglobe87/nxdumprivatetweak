package com.nxdump

import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.DocumentsContract
import com.nxdump.core.Dumper
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream

/** Writtes files via high-speed native POSIX I/O, bypassing SAF overhead and dropping a .nomedia tag. */
class SafSink(private val ctx: Context, private val tree: Uri, wantedName: String) : Dumper.Sink {
    private val resolver = ctx.contentResolver
    private val dirs = HashMap<String, Uri>()
    private val nativeDirs = HashMap<String, File>()
    val topName: String
    private val nativeBaseDir: File?

    init {
        var name = wantedName
        val treeId = try { DocumentsContract.getTreeDocumentId(tree) } catch (e: Exception) { "" }
        
        val candidateDir = if (treeId.contains("primary:")) {
            val subPath = treeId.substringAfter("primary:")
            File(Environment.getExternalStorageDirectory(), subPath)
        } else {
            null
        }

        if (candidateDir != null && candidateDir.exists() && candidateDir.canWrite()) {
            var target = File(candidateDir, name)
            var n = 2
            while (target.exists()) {
                name = "$wantedName ($n)"
                target = File(candidateDir, name)
                n++
            }
            target.mkdirs()
            File(target, ".nomedia").createNewFile()
            nativeBaseDir = target
            topName = name
        } else {
            nativeBaseDir = null
            val root = DocumentsContract.buildDocumentUriUsingTree(tree, treeId)
            var n = 2
            while (findChild(root, name) != null) name = "$wantedName ($n)".also { n++ }
            topName = name
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

    private fun safDir(path: String): Uri {
        dirs[path]?.let { return it }
        val parent = safDir(path.substringBeforeLast('/', ""))
        val name = path.substringAfterLast('/')
        val u = findChild(parent, name) ?: createSafDoc(parent, DocumentsContract.Document.MIME_TYPE_DIR, name)
        dirs[path] = u
        return u
    }

    private fun nativeDir(path: String): File {
        nativeDirs[path]?.let { return it }
        val base = nativeBaseDir ?: throw IOException("Native base missing")
        val d = if (path.isEmpty()) base else File(base, path)
        if (!d.exists()) d.mkdirs()
        nativeDirs[path] = d
        return d
    }

    override fun open(relativePath: String): OutputStream {
        val subDir = relativePath.substringBeforeLast('/', "")
        val fileName = relativePath.substringAfterLast('/')

        return if (nativeBaseDir != null) {
            val dir = nativeDir(subDir)
            val targetFile = File(dir, fileName)
            BufferedOutputStream(FileOutputStream(targetFile), 1 shl 22) // 4MB buffer for max speed
        } else {
            val d = safDir(subDir)
            val f = createSafDoc(d, "application/octet-stream", fileName)
            val os = resolver.openOutputStream(f, "w") ?: throw IOException("Cannot write $relativePath")
            BufferedOutputStream(os, 1 shl 22)
        }
    }
}
