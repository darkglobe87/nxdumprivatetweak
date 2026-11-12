package com.nxdump.core;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Extracts ExeFS / RomFS, optionally with an update merged on top. */
public final class Dumper {
    private Dumper() {}

    /** Set to true to ALWAYS dump RomFS as a single romfs.bin file, or name your output folder ending in "_bin". */
    public static final boolean ALWAYS_DUMP_ROMFS_BIN = false;

    public interface Sink { OutputStream open(String relativePath) throws IOException; }

    public interface Progress {
        void update(String file, long done, long total);
        boolean cancelled();
    }

    private static final class Job {
        final String path; final Source src; final long off, size;
        Job(String path, Source src, long off, long size) { this.path = path; this.src = src; this.off = off; this.size = size; }
    }

    /** Header-based lookup (fallback). */
    private static Nca findProgram(List<Nca> ncas, long appId, boolean patch) {
        Nca best = null;
        for (Nca n : ncas) {
            if (n.contentType != Nca.TYPE_PROGRAM || Analyzer.appIdOf(n.titleId) != appId) continue;
            int low = (int) (n.titleId & 0x1FFF);
            boolean isPatch = low >= 0x800 && low < 0x1000;
            if (isPatch != patch) continue;
            if (best == null || n.titleId < best.titleId) best = n;
        }
        return best;
    }

    /** Finds the program NCA via the CNMT content list; falls back to NCA header heuristics. */
    private static Nca resolveProgram(Container c, Keys keys, long appId, boolean patch, List<String> errs) {
        List<Nca> ncas = c.openNcas(keys, errs);
        int kind = patch ? Analyzer.UPDATE : Analyzer.BASE;
        for (Analyzer.Info i : Analyzer.analyze(c, keys))
            if (i.kind == kind && i.appId == appId && i.programNca != null)
                for (Nca n : ncas) if (n.name.equalsIgnoreCase(i.programNca)) return n;
        Nca n = findProgram(ncas, appId, patch);
        if (n != null) return n;
        Nca any = null;
        for (Nca x : ncas) {
            if (x.contentType != Nca.TYPE_PROGRAM) continue;
            if (patch ? x.isPatchRomFs() : !x.isPatchRomFs() && Analyzer.appIdOf(x.titleId) == appId) { any = x; break; }
        }
        return any;
    }

    private static long readLe64(byte[] b, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (b[off + i] & 0xFFL);
        return v;
    }

    /** update may be null, or be the same Container as base (bundle NSP). */
    public static void dump(Container base, Container update, long appId, boolean exefs, boolean romfs,
                            Keys keys, Sink sink, Progress prog) throws IOException {
        base.importTickets(keys);
        List<String> errs = new ArrayList<>();
        if (update != null) update.importTickets(keys);
        Nca baseProg = resolveProgram(base, keys, appId, false, errs);
        if (baseProg == null) throw new NxException("Base game program data not found in the selected file");
        Nca updProg = null;
        if (update != null) {
            updProg = resolveProgram(update, keys, appId, true, errs);
            if (updProg == null) throw new NxException("Could not find this game's program data in the update file \"" + update.fileName + "\"" + (errs.isEmpty() ? "" : " (" + errs.get(0) + ")") + ". Check the update is for this exact game and your keys are new enough.");
        }

        List<Job> jobs = new ArrayList<>();
        if (exefs) {
            Nca n = updProg != null ? updProg : baseProg;
            Nca.Section s = n.section(Nca.FS_PFS);
            if (s == null) throw new NxException("ExeFS section not found");
            Source d = n.openData(s);
            for (Pfs.Entry e : Pfs.parse(d)) jobs.add(new Job("exefs/" + e.name, d, e.offset, e.size));
        }
        Source romfsImg = null;
        long maxRomfsEnd = 0;
        if (romfs) {
            Nca.Section bs = baseProg.section(Nca.FS_ROMFS);
            Nca.Section us = updProg != null ? updProg.section(Nca.FS_ROMFS) : null;
            if (us != null && us.encType == Nca.ENC_CTR_EX) {
                if (bs == null) throw new NxException("Base game has no RomFS to patch");
                romfsImg = updProg.openPatchedRomFs(us, baseProg.openSection(bs));
            } else if (us != null) {
                romfsImg = updProg.openData(us);
            } else if (bs != null) {
                romfsImg = baseProg.openData(bs);
            } else {
                throw new NxException("RomFS section not found");
            }

            // Read 80-byte RomFS header to get minimum image boundary
            byte[] hdr = new byte[0x50];
            romfsImg.read(0, hdr, 0, 0x50);
            long metaEnd = readLe64(hdr, 0x38) + readLe64(hdr, 0x40);
            long dataOff = readLe64(hdr, 0x48);
            maxRomfsEnd = Math.max(metaEnd, dataOff);

            List<Job> romfsJobs = new ArrayList<>();
            for (RomFs.File f : RomFs.list(romfsImg)) {
                romfsJobs.add(new Job("romfs/" + f.path, romfsImg, f.offset, f.size));
                long end = f.offset + f.size;
                if (end > maxRomfsEnd) maxRomfsEnd = end;
            }

            // Check if single-file romfs.bin mode is requested
            boolean dumpAsBin = ALWAYS_DUMP_ROMFS_BIN;
            if (!dumpAsBin) {
                try {
                    java.lang.reflect.Field f = sink.getClass().getDeclaredField("topName");
                    f.setAccessible(true);
                    Object v = f.get(sink);
                    if (v != null && v.toString().toLowerCase().contains("_bin")) dumpAsBin = true;
                } catch (Throwable ignored) {}
            }

            if (dumpAsBin) {
                jobs.add(new Job("romfs.bin", romfsImg, 0, maxRomfsEnd));
            } else {
                romfsJobs.sort(Comparator.comparingLong(j -> j.off));
                jobs.addAll(romfsJobs);
            }
        }
        if (jobs.isEmpty()) throw new NxException("Nothing to extract");

        long total = 0;
        for (Job j : jobs) total += j.size;
        final long totalBytes = total;
        final AtomicLong doneBytes = new AtomicLong(0);

        final int BUF_SIZE = 1 << 23; // 8 MB buffer & read-ahead window
        final int ASYNC_MAX_FILE = 1 << 20; // 1 MB threshold for parallel async file writer
        byte[] buf = new byte[BUF_SIZE];
        byte[] cacheBuf = new byte[BUF_SIZE];
        Source cacheSrc = null;
        long cacheStart = -1;
        long cacheEnd = -1;

        // 8-thread parallel I/O writer pool for small loose files
        ExecutorService writerPool = Executors.newFixedThreadPool(8);
        final Semaphore inFlightBytes = new Semaphore(32 * 1024 * 1024); // Cap queue at 32 MB RAM
        final AtomicReference<IOException> asyncErr = new AtomicReference<>(null);

        try {
            for (Job j : jobs) {
                if (prog.cancelled()) throw new InterruptedIOException("Cancelled");
                IOException prevErr = asyncErr.get();
                if (prevErr != null) throw prevErr;

                // Fast parallel path for small RomFS files (<= 1 MB)
                if (j.src == romfsImg && j.size <= ASYNC_MAX_FILE) {
                    final byte[] fileData = new byte[(int) j.size];
                    if (j.size > 0) {
                        if (cacheSrc != j.src || j.off < cacheStart || j.off + j.size > cacheEnd) {
                            long alignedOff = j.off & ~15L;
                            int toRead = (int) Math.min((long) BUF_SIZE, maxRomfsEnd - alignedOff);
                            if (toRead >= (j.off - alignedOff) + j.size) {
                                j.src.read(alignedOff, cacheBuf, 0, toRead);
                                cacheSrc = j.src;
                                cacheStart = alignedOff;
                                cacheEnd = alignedOff + toRead;
                            }
                        }
                        if (cacheSrc == j.src && j.off >= cacheStart && j.off + j.size <= cacheEnd) {
                            System.arraycopy(cacheBuf, (int) (j.off - cacheStart), fileData, 0, (int) j.size);
                        } else {
                            j.src.read(j.off, fileData, 0, (int) j.size);
                        }
                    }

                    final int permits = Math.max(1, (int) j.size);
                    try {
                        inFlightBytes.acquire(permits);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new InterruptedIOException("Cancelled");
                    }

                    final String jobPath = j.path;
                    final long jobSize = j.size;
                    writerPool.execute(() -> {
                        try {
                            if (asyncErr.get() == null && !prog.cancelled()) {
                                try (OutputStream out = sink.open(jobPath)) {
                                    if (jobSize > 0) out.write(fileData);
                                }
                                long d = doneBytes.addAndGet(jobSize);
                                prog.update(jobPath, d, totalBytes);
                            }
                        } catch (IOException e) {
                            asyncErr.compareAndSet(null, e);
                        } catch (Throwable t) {
                            asyncErr.compareAndSet(null, new IOException(t.getMessage(), t));
                        } finally {
                            inFlightBytes.release(permits);
                        }
                    });
                    continue;
                }

                // Direct 8 MB streaming path for large files and romfs.bin
                prog.update(j.path, doneBytes.get(), totalBytes);
                try (OutputStream out = sink.open(j.path)) {
                    long p = 0;
                    while (p < j.size) {
                        if (prog.cancelled()) throw new InterruptedIOException("Cancelled");
                        IOException err = asyncErr.get();
                        if (err != null) throw err;
                        int n = (int) Math.min(buf.length, j.size - p);
                        j.src.read(j.off + p, buf, 0, n);
                        out.write(buf, 0, n);
                        p += n;
                        long d = doneBytes.addAndGet(n);
                        prog.update(j.path, d, totalBytes);
                    }
                }
            }
        } finally {
            writerPool.shutdown();
            try {
                while (!writerPool.awaitTermination(200, TimeUnit.MILLISECONDS)) {
                    if (prog.cancelled()) {
                        writerPool.shutdownNow();
                        break;
                    }
                }
            } catch (InterruptedException e) {
                writerPool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        IOException finalErr = asyncErr.get();
        if (finalErr != null) throw finalErr;
        if (prog.cancelled()) throw new InterruptedIOException("Cancelled");
        prog.update("", totalBytes, totalBytes);
    }
}
