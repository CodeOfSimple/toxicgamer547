package com.zane.smapiinstaller.utils;

import com.google.common.base.Splitter;

import org.apache.commons.lang3.StringUtils;

import java.util.List;

/**
 * 版本比较工具
 * @author Zane
 */
public class VersionUtil {
    /**
     * 比较单个版本段
     * @param sectionA sectionA
     * @param sectionB sectionB
     * @return 比较结果
     */
    private static int compareVersionSection(String sectionA, String sectionB) {
        try {
            return Integer.compare(Integer.parseInt(sectionA), Integer.parseInt(sectionB));
        } catch (Exception ignored) {
        }
        List<String> listA = Splitter.on("-").splitToList(sectionA);
        List<String> listB = Splitter.on("-").splitToList(sectionB);
        int i;
        for (i = 0; i < listA.size() && i < listB.size(); i++) {
            Integer intA = null;
            Integer intB = null;
            try {
                intA = Integer.parseInt(listA.get(i));
                return Integer.compare(intA, Integer.parseInt(listB.get(i)));
            } catch (Exception ignored) {
                try {
                