package com.zane.smapiinstaller.dto;

import android.util.Log;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.zane.smapiinstaller.constant.Constants;
import com.zane.smapiinstaller.entity.ModManifestEntry;

import org.apache.commons.lang3.RegExUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.List;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * @author Zane
 */
@Data
@RequiredArgsConstructor
public class ModUpdateCheckRequestDto {

    public ModUpdateCheckRequestDto(List<ModInfo> mods, SemanticVersion gameVersion) {
        this.mods = mods;
        this.gameVersion = gameVersion;
    }

    /**
     * 待检查MOD列表
     */
    @NonNull
    private List<ModInfo> mods;
    /**
     * SMAPI版本
     */
    private SemanticVersion apiVersion = new SemanticVersion(Constants.SMAPI_VERSION);
    /**
     * 游戏版本
     */
    private SemanticVersion gameVersion;
    /**
     * 平台版本
     */
    private String platform = Constants.PLATFORM;
    /**
     * 是否拉取MOD详情
     */
    private boolean includeExtendedMetadata = false;

    @Data
    @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE)
    public static class SemanticVersion {
        private int MajorVersion;
        private int MinorVersion;
        private int PatchVersion;
        private int PlatformRelease;
        private String PrereleaseTag;
        private String BuildMetadata;

        public SemanticVersion(String versionStr) {
            // init
            MajorVersion = 0;
            MinorVersion = 0;
            PatchVersion = 0;
            PlatformRelease = 0;
            PrereleaseTag = null;
            BuildMetadata = null;
            // normalize
            versionStr = StringUtils.trim(versionStr);
            if (StringUtils.isBlank(versionStr)) {
                return;
            }
            List<String> versionSections = Splitter.on(CharMatcher.anyOf(".-+")).splitToList(versionStr);
            // read major/minor version
    