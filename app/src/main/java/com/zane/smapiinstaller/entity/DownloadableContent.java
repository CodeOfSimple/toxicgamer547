
package com.zane.smapiinstaller.entity;

import lombok.Data;

/**
 * 可下载内容包
 * @author Zane
 */
@Data
public class DownloadableContent {
    /**
     * 类型，COMPAT:兼容包/LOCALE:语言包
     */
    private String type;