package com.zane.smapiinstaller.logic;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.view.View;

import com.microsoft.appcenter.crashes.Crashes;
import com.zane.smapiinstaller.R;
import com.zane.smapiinstaller.constant.Constants;
import com.zane.smapiinstaller.utils.DialogUtils;

/**
 * 游戏启动器
 * @author Zane
 */
public class GameLauncher {

    private final View root;

    public GameLauncher(View root) {
        this.root = root;
    }

    /**
     * 检查已安装MOD版本游戏
     * @param context 上下文
     * @return 软件包信息
     */
    public static PackageInfo getGamePackageInfo(Activity context) {
        PackageManager packageManager = context.getPackageManager();
        try {
            PackageInfo packageInfo;
            try {
                packageInfo = packageManager.getPackageInfo(Constants.TARGET_PACKAGE_NAME, 0);
            } catch (PackageManager.NameNotFoundException ignored) {
                packageInfo = packageManager.getPackageInfo(Constants.TARGET_PACKAGE_NAME_SAMSUNG, 0);
            }
            return packageInfo;
        } catch (PackageM