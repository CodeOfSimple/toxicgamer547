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

package com.android.apksig.internal.util;

import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.ReadableDataSink;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Growable byte array which can be appended to via {@link DataSink} interface and read from via
 * {@link DataSource} interface.
 */
public class ByteArrayDataSink implements ReadableDataSink {

    private static final int MAX_READ_CHUNK_SIZE = 65536;

    private byte[] mArray;
    private int mSize;

    public ByteArrayDataSink() {
        this(65536);
    }

    public ByteArrayDataSink(int initialCapacity) {
        if (initialCapacity < 0) {
            throw new IllegalArgumentException("initial capacity: " + initialCapacity);
        }
        mArray = new byte[initialCapacity];
    }

    @Override
    public void consume(byte[] buf, int offset, int length) throws IOException {
        if (offset < 0) {
            // Must perform this check because System.arraycopy below doesn't perform it when
            // length == 0
            throw new IndexOutOfBoundsException("offset: " + offset);
        }
        if (offset > buf.length) {
            // Must perform this check because System.arraycopy below doesn't perform it when
            // length == 0
            throw new IndexOutOfBoundsException(
                    "offset: " + offset + ", buf.length: " + buf.length);
        }
        if (length == 0) {
            return;
        }

        ensureAvailable(length);
        System.arraycopy(buf, offset, mArray, mSize, length);
        mSize += length;
    }

    @Override
    public void consume(ByteBuffer buf) throws IOException {
        if (!buf.hasRemaining()) {
            return;
        }

        if (buf.hasArray()) {
            consume(buf.array(), buf.arrayOffset() + buf.position(), buf.remaining());
            buf.position(buf.limit());
            return;
        }

        ensureAvailable(buf.remaining());
        byte[] tmp = new byte[Math.min(buf.remaining(), MAX_READ_CHUNK_SIZE)];
        while (buf.hasRemaining()) {
            int chunkSize = Math.min(buf.remaining(), tmp.length);
            buf.get(tmp, 0, chunkSize);
            System.arraycopy(tmp, 0, mArray, mSize, chunkSize);
            mSize += chunkSize;
        }
    }

    private void ensureAvailable(int minAvailable) throws IOException {
        if (minAvailable <= 0) {
            return;
        }

        long minCapacity = ((long) mSize) + minAvailable;
        if (minCapacity <= mArr