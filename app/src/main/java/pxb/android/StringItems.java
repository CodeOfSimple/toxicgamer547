/*
 * Copyright (c) 2009-2013 Panxiaobo
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pxb.android;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("serial")
public class StringItems extends ArrayList<StringItem> {
	private static final int UTF8_FLAG = 0x00000100;

	
    public static String[] read(ByteBuffer in) throws IOException {
        int trunkOffset = in.position() - 8;
        int stringCount = in.getInt();
        int styleOffsetCount = in.getInt();
        int flags = in.getInt();
        int stringDataOffset = in.getInt();
        int stylesOffset = in.getInt();
        int offsets[] = new int[stringCount];
        String strings[] = new String[stringCount];
        for (int i = 0; i < stringCount; i++) {
            offsets[i] = in.getInt();
        }

        int base = trunkOffset + stringDataOffset;
        for (int i = 0; i < offsets.length; i++) {
            in.position(base + offsets[i]);
            String s;

            if (0 != (flags & UTF8_FLAG)) {
                u8length(in); // ignored
                int u8len = u8length(in);
                int start = in.position();
                int blength = u8len;
                while (in.get(start + blength) != 0) {
                    blength++;
                }
                s = new String(in.array(), start, blength, "UTF-8");
            } else {
                int length = u16length(in);
                s = new String(in.array(), in.position(), length * 2, "UTF-16LE");
  