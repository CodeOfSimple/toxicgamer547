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

package com.android.apksig.util;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Abstract representation of a source of data.
 *
 * <p>This abstraction serves three purposes:
 * <ul>
 * <li>Transparent handling of different types of sources, such as {@code byte[]},
 *     {@link java.nio.ByteBuffer}, {@link java.io.RandomAccessFile}, memory-mapped file.</li>
 * <li>Support sources larger than 2 GB. If all sources were smaller than 2 GB, {@code ByteBuffer}
 *     may have worked as the unifying abstraction.</li>
 * <li>Support sources which do not fit into logical memory as a contiguous region.</li>
 * </ul>
 *
 * <p>There are following ways to obtain a chunk of data from the data source:
 * <ul>
 * <li>Stream the chunk's data into a {@link DataSink} using
 *     {@link #feed(long, long, DataSink) feed}. This is best suited for scenarios where there is no
 *     need to have the chunk's data accessible at the same time, for example, when computing the
 *     digest of the chunk. If you need to keep the chunk's data around after {@code feed}
 *     completes, you must create a copy during {@code feed}. However, in that case the following
 *     methods of obtaining the chunk's data may be more appropriate.</li>
 * <li>Obtain a {@link ByteBuffer} containing the chunk's data using
 *     {@link #getByteBuffer(long, int) getByteBuffer}. Depending on the data source, the chunk's
 *     data may or may not be copied by this operatio