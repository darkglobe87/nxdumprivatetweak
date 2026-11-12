package com.nxdump.core;

import java.io.IOException;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

/** Nintendo Content Archive: header decryption, key derivation, section access (incl. BKTR patches). */
public final class Nca {
    public static final int TYPE_PROGRAM = 0, TYPE_META = 1, TYPE_CONTROL = 2, TYPE_MANUAL = 3, TYPE_DATA = 4;
    public static final int FS_ROMFS = 0, FS_PFS = 1;
    public static final int ENC_NONE = 1, ENC_CTR = 3, ENC_CTR_EX = 4;

    public static final class Section {
        public final int index;
        public final long start, end;
        public final int fsType, hashType, encType;
        final byte[] hdr;

        Section(int index, long start, long end, byte[] hdr) {
            this.index = index; this.start = start; this.end = end; this.hdr = hdr;
            this.fsType = hdr[2] & 0xFF; this.hashType = hdr[3] & 0xFF; this.encType = hdr[4] & 0xFF;
        }
        public boolean exists() { return end > start; }
        public long size() { return end - start; }
    }

    public final String name;
    public final int contentType;
    public final long titleId;
    public final long size;
    public final Section[] sections = new Section[4];

    private final Source src;
    private final Keys keys;
    private final byte[] rightsId = new byte[16];
    private final byte[] keyArea = new byte[0x40];
    private final int keyGen, kakIndex;
    private byte[] contentKey;
    private SecretKeySpec contentKeySpec;

    public Nca(Source src, Keys keys, String name) throws IOException {
        this.src = src; this.keys = keys; this.name = name;
        if (src.size() < 0xC00) throw new NxException(name + ": too small to be an NCA");
        byte[] h = src.read(0, 0xC00);
        byte[] hk = keys.headerKey();
        Aes.xtsDecrypt(hk, h, 0, 0x400, 0);
        if (Bin.magic(h, 0x200, "NCA3")) {
            Aes.xtsDecrypt(hk, h, 0x400, 0x800, 2);
        } else if (Bin.magic(h, 0x200, "NCA2")) {
            for (int i = 0; i < 4; i++) Aes.xtsDecrypt(hk, h, 0x400 + i * 0x200, 0x200, 0);
        } else {
            throw new NxException(name + ": cannot decrypt NCA header (wrong header_key, or NCA0/unsupported)");
        }
        contentType = h[0x205] & 0xFF;
        kakIndex = h[0x207] & 0xFF;
        size = Bin.le64(h, 0x208);
        titleId = Bin.le64(h, 0x210);
        int g = Math.max(h[0x206] & 0xFF, h[0x220] & 0xFF);
        keyGen = g > 0 ? g - 1 : 0;
        System.arraycopy(h, 0x230, rightsId, 0, 16);
        System.arraycopy(h, 0x300, keyArea, 0, 0x40);
        for (int i = 0; i < 4; i++) {
            long s = (Bin.le32(h, 0x240 + i * 16) & 0xFFFFFFFFL) * 0x200;
            long e = (Bin.le32(h, 0x244 + i * 16) & 0xFFFFFFFFL) * 0x200;
            sections[i] = new Section(i, s, e, Arrays.copyOfRange(h, 0x400 + i * 0x200, 0x600 + i * 0x200));
        }
    }

    public boolean hasRightsId() { for (byte b : rightsId) if (b != 0) return true; return false; }
    public String rightsIdHex() { return Bin.hex(rightsId); }

    /** True if this is an update NCA (RomFS stored as a BKTR patch). */
    public boolean isPatchRomFs() {
        Section s = section(FS_ROMFS);
        return s != null && s.encType == ENC_CTR_EX;
    }

    /** First existing section with the given fs type, or null. */
    public Section section(int fsType) {
        for (Section s : sections) if (s.exists() && s.fsType == fsType) return s;
        return null;
    }

    private byte[] contentKey() throws IOException {
        if (contentKey != null) return contentKey;
        if (hasRightsId()) {
            byte[] enc = keys.titleKey(rightsIdHex());
            if (enc == null)
                throw new NxException(name + ": no title key for rights id " + rightsIdHex()
                        + " (add title.keys or place the .tik in the same NSP)");
            contentKey = Aes.ecbDecrypt(keys.titlekek(keyGen), enc);
        } else {
            byte[] area = Aes.ecbDecrypt(keys.kak(kakIndex, keyGen), keyArea);
            contentKey = Arrays.copyOfRange(area, 0x20, 0x30);
        }
        contentKeySpec = new SecretKeySpec(contentKey, "AES");
        return contentKey;
    }

    private SecretKeySpec contentKeySpec() throws IOException {
        if (contentKeySpec == null) contentKey();
        return contentKeySpec;
    }

    private static byte[] upper16(Section s) {
        byte[] u = new byte[16];
        for (int i = 0; i < 8; i++) u[i] = s.hdr[0x140 + 7 - i];
        return u;
    }

    /** Decrypted section contents (offset 0 = start of section). */
    public Source openSection(Section s) throws IOException {
        if (s == null || !s.exists()) throw new NxException(name + ": section missing");
        Source raw = new CachedSource(src.slice(s.start, s.size()));
        switch (s.encType) {
            case ENC_NONE: return raw;
            case 0:
            case ENC_CTR: return new Ctr(raw, contentKeySpec(), upper16(s), s.start);
            case ENC_CTR_EX: throw new NxException(name + ": patch section needs a base game");
            default: throw new NxException(name + ": unsupported section encryption " + s.encType);
        }
    }

    /** The filesystem payload of a section: PFS0 image, or RomFS image inside the IVFC layout. */
    public Source openData(Section s) throws IOException { return fsData(s, openSection(s)); }

    Source fsData(Section s, Source decrypted) throws IOException {
        long off, len;
        if (s.hashType == 2 || s.hashType == 5) { off = Bin.le64(s.hdr, 0x40); len = Bin.le64(s.hdr, 0x48); }
        else if (s.hashType == 3 || s.hashType == 6) { off = Bin.le64(s.hdr, 0x90); len = Bin.le64(s.hdr, 0x98); }
        else throw new NxException(name + ": unsupported hash layout " + s.hashType);
        if (off < 0 || len <= 0) throw new NxException(name + ": corrupt section layout");
        return decrypted.slice(off, len);
    }

    /** RomFS image of an update NCA merged on top of the base game's decrypted RomFS section. */
    public Source openPatchedRomFs(Section patchSec, Source baseSection) throws IOException {
        byte[] h = patchSec.hdr;
        long relOff = Bin.le64(h, 0x100), relSize = Bin.le64(h, 0x108);
        long subOff, subSize;
        int relCnt, subCnt;
        if (Bin.magic(h, 0x110, "BKTR")) {          // interleaved layout
            relCnt = Bin.le32(h, 0x118);
            subOff = Bin.le64(h, 0x120); subSize = Bin.le64(h, 0x128); subCnt = Bin.le32(h, 0x138);
        } else {                                     // grouped layout
            subOff = Bin.le64(h, 0x110); subSize = Bin.le64(h, 0x118);
            relCnt = Bin.le32(h, 0x128); subCnt = Bin.le32(h, 0x138);
        }
        if (relCnt <= 0 || subCnt <= 0) throw new NxException(name + ": patch has no BKTR tables");

        Source raw = new CachedSource(src.slice(patchSec.start, patchSec.size()));
        SecretKeySpec ks = contentKeySpec();
        byte[] up = upper16(patchSec);
        Source plain = new Ctr(raw, ks, up, patchSec.start);   // tables use the plain section counter

        long[] virt = new long[relCnt];
        long[] phys = new long[relCnt];
        int[] stor = new int[relCnt];
        readRelocTree(plain, relOff, relSize, relCnt, virt, phys, stor);

        long[] subOffs = new long[subCnt];
        int[] subCtr = new int[subCnt];
        readSubTree(plain, subOff, subSize, subCnt, subOffs, subCtr);

        Source patchData = new CtrEx(raw, ks, up, patchSec.start, subOffs, subCtr);
        return fsData(patchSec, new Patched(virt, phys, stor, baseSection, patchData));
    }

    private static void readRelocTree(Source s, long off, long size, int count,
                                      long[] virt, long[] phys, int[] stor) throws IOException {
        if (size <= 0 || size > (64 << 20)) throw new NxException("Corrupt BKTR table");
        byte[] t = s.read(off, (int) size);
        final int nodeSize = 0x4000;
        final int entrySize = 20;
        int offsetCount = (nodeSize - 16) / 8;
        int perSet = (nodeSize - 16) / entrySize;
        int sets = (count + perSet - 1) / perSet;
        long nodeStorage = sets <= offsetCount ? nodeSize : (long) ((sets + offsetCount - 1) / offsetCount + 1) * nodeSize;
        int idx = 0;
        for (int si = 0; si < sets && idx < count; si++) {
            int base = (int) (nodeStorage + (long) si * nodeSize);
            if (base + 16 > t.length) throw new NxException("Corrupt BKTR table");
            int cnt = Bin.le32(t, base + 4);
            for (int k = 0; k < cnt && idx < count; k++) {
                int p = base + 16 + k * entrySize;
                if (p + entrySize > t.length) throw new NxException("Corrupt BKTR table");
                virt[idx] = Bin.le64(t, p);
                phys[idx] = Bin.le64(t, p + 8);
                stor[idx] = Bin.le32(t, p + 16);
                idx++;
            }
        }
        if (idx != count) throw new NxException("BKTR entry count mismatch");
    }

    private static void readSubTree(Source s, long off, long size, int count,
                                    long[] subOffs, int[] subCtr) throws IOException {
        if (size <= 0 || size > (64 << 20)) throw new NxException("Corrupt BKTR table");
        byte[] t = s.read(off, (int) size);
        final int nodeSize = 0x4000;
        final int entrySize = 16;
        int offsetCount = (nodeSize - 16) / 8;
        int perSet = (nodeSize - 16) / entrySize;
        int sets = (count + perSet - 1) / perSet;
        long nodeStorage = sets <= offsetCount ? nodeSize : (long) ((sets + offsetCount - 1) / offsetCount + 1) * nodeSize;
        int idx = 0;
        for (int si = 0; si < sets && idx < count; si++) {
            int base = (int) (nodeStorage + (long) si * nodeSize);
            if (base + 16 > t.length) throw new NxException("Corrupt BKTR table");
            int cnt = Bin.le32(t, base + 4);
            for (int k = 0; k < cnt && idx < count; k++) {
                int p = base + 16 + k * entrySize;
                if (p + entrySize > t.length) throw new NxException("Corrupt BKTR table");
                subOffs[idx] = Bin.le64(t, p);
                subCtr[idx] = Bin.le32(t, p + 12);
                idx++;
            }
        }
        
