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
        if (initialCapacity < 0) 