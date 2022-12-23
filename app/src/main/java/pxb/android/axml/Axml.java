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

import java.util.ArrayList;
import java.util.List;

public class Axml extends AxmlVisitor {

    public static class Node extends NodeVisitor {
        public static class Attr {
            public String ns, name;
            public int resourceId, type;
            public Object value;

            public void accept(NodeVisitor nodeVisitor) {
                nodeVisitor.attr(ns, name, resourceId, type, value);
            }
        }

        public static class Text {
            public int ln;
            public String text;

            public void accept(NodeVisitor nodeVisitor) {
                nodeVisitor.text(ln, text);
            }
        }

        public List<Attr> attrs = new ArrayList<Attr>();
        public List<Node> children = new ArrayList<Node>();
        public Integer ln;
        