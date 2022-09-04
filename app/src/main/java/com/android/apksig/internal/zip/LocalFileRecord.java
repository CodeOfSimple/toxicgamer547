/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.apksig.internal.zip;

import com.android.apksig.internal.util.ByteBufferSink;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipFormatException;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * ZIP Local File record.
 *
 * <p>The record consists of the Local File Header, file data, and (if present) Data Descriptor.
 */
public class LocalFileRecord {
    private static final int RECORD_SIGNATURE = 0x04034b50;
    private static final int HEADER_SIZE_BYTES = 30;

    private static final int GP_FLAGS_OFFSET = 6;
    private static final int CRC32_OFFSET = 14;
    private static final int COMPRESSED_SIZE_OFFSET = 18;
    private static final int UNCOMPRESSED_SIZE_OFFSET = 22;
    private static final int NAME_LENGTH_OFFSET = 26;
    private static final int EXTRA_LENGTH_OFFSET = 28;
    private static final int NAME_OFFSET = HEADER_SIZE_BYTES;

    private static final int DATA_DESCRIPTOR_SIZE_BYTES_WITHOUT_SIGNATURE = 12;
    private static final int DATA_DESCRIPTOR_SIGNATURE = 0x08074b50;

    private final String mName;
    private final int mNameSizeBytes;
    private final ByteBuffer mExtra;

    private final long mStartOffsetInArchive;
    private final long mSize;

    private final int mDataStartOffset;
    private final long mDataSize;
    private final boolean mDataCompressed;
    private final long mUncompressedDataSize;

    private LocalFileRecord(
            String name,
            int nameSizeBytes,
            ByteBuffer extra,
            long startOffsetInArchive,
            long size,
            int dataStartOffset,
            long dataSize,
            boolean dataCompressed,
            long uncompressedDataSize) {
        mName = name;
        mNameSizeBytes = nameSizeBytes;
        mExtra = extra;
        mStartOffsetInArchive = startOffsetInArchive;
        mSize = size;
        mDataStartOffset = dataStartOffset;
        mDataSize = dataSize;
        mDataCompressed = dataCompressed;
        mUncompressedDataSize = uncompressedDataSize;
    }

    public String getName() {
        return mName;
    }

    public ByteBuffer getExtra() {
        return (mExtra.capacity() > 0) ? mExtra.slice() : mExtra;
    }

    public int getExtraFieldStartOffsetInsideRecord() {
        return HEADER_SIZE_BYTES + mNameSizeBytes;
    }

    public long getStartOffsetInArchive() {
        return mStartOffsetInArchive;
    }

    public int getDataStartOffsetInRecord() {
        return mDataStartOffset;
    }

    /**
     * Returns the size (in bytes) of this record.
     */
    public long getSize() {
        return mSize;
    }

    /**
     * Returns {@code true} if this record's file data is stored in compressed form.
     */
    public boolean isDataCompressed() {
        return mDataCompressed;
    }

    /**
     * Returns the Local File record starting at the current position of the provided buffer
     * and advances the buffer's position immediately past the end of the record. The record
     * consists of the Local File Header, data, and (if present) Data Descriptor.
     */
    public static LocalFileRecord getRecord(
            DataSource apk,
            CentralDirectoryRecord cdRecord,
            long cdStartOffset) throws ZipFormatException, IOException {
        return getRecord(
                apk,
                cdRecord,
                cdStartOffset,
                true, // obtain extra field contents
                true // include Data Descriptor (if present)
                );
    }

    /**
     * Returns the Local File record starting at the current position of the provided buffer
     * and advances the buffer's position immediately past the end of the record. The record
     * consists of the Local File Header, data, and (if present) Data Descriptor.
     */
    private static LocalFileRecord getRecord(
            DataSource apk,
            CentralDirectoryRecord cdRecord,
            long cdStartOffset,
            boolean extraFieldContentsNeeded,
            boolean dataDescriptorIncluded) throws ZipFormatException, IOException {
        // IMPLEMENTATION NOTE: This method attempts to mimic the behavior of Android platform
        // exhibited when reading an APK for the purposes of verifying its signatures.

        String entryName = cdRecord.getName();
        int cdRecordEntryNameSizeBytes = cdRecord.getNameSizeBytes();
        int headerSizeWithName = HEADER_SIZE_BYTES + cdRecordEntryNameSizeBytes;
        long headerStartOffset = cdRecord.getLocalFileHeaderOffset();
        long headerEndOffset = headerStartOffset + headerSizeWithName;
        if (headerEndOffset > cdStartOffset) {
            throw new ZipFormatException(
                    "Local File Header of " + entryName + " extends beyond start of Central"
                            + " Directory. LFH end: " + headerEndOffset
                            + ", CD start: " + cdStartOffset);
        }
        ByteBuffer header;
        try {
            header = apk.getByteBuffer(headerStartOffset, headerSizeWithName);
        } catch (IOException e) {
            throw new IOExcept