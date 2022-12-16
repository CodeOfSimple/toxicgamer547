package com.zane.smapiinstaller.utils;

/**
 * @author Zane
 */
public class StringUtils extends org.apache.commons.lang3.StringUtils {

    public static boolean wildCardMatch(String str, String pattern) {
        int i = 0;
        int j = 0;
        int starIndex = -1;
        int iI