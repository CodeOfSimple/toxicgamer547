/*
 * Copyright (c) 2009-2013 Panxiaobo
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
package pxb.android.axml;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

public class Util {
    public static byte[] readFile(File in) throws IOException {
        InputStream is = new FileInputStream(in);
        byte[] xml = new byte[is.available()];
        is.read(xml);
        is.close();
        return xml;
    }

    public static byte[] readIs(InputStream is) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        copy(is, os);
        return os.toByteArray();
    }

    public static void writeFile(byte[] data, File out) throws IOException {
        FileOutputStream fos = new FileOutputStream(out);
        fos.write(data);
        fos.close();
    }

    public static Map<String, String> readProguardConfig(File config) throws IOException {
        Map<String, String> clzMap = new HashMap<String, String>();
        BufferedReader r = new BufferedReader(new InputStreamRea