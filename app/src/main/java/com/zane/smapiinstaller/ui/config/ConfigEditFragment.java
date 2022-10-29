package com.zane.smapiinstaller.ui.config;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.webkit.WebViewAssetLoader;

import com.hjq.language.MultiLanguages;
import com.zane.smapiinstaller.BuildConfig;
import com.zane.smapiinstaller.R;
import com.zane.smapiinstaller.constant.Constants;
import com.zane.smapiinstaller.constant.DialogAction;
import com.zane.smapiinstaller.databinding.FragmentConfigEditBinding;
import com.zane.smapiinstaller.dto.JsonEditorObject;
import com.zane.smapiinstaller.dto.KeyboardEditorObject;
import com.zane.smapiinstaller.logic.CommonLogic;
import com.zane.smapiinstaller.utils.DialogUtils;
import com.zane.smapiinstaller.utils.FileUtils;
import com.zane.smapiinstaller.utils.JsonUtil;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.core.content.FileProvider;
import androidx.fragment.app.Fragment;
import androidx.navigation.Navigation;

/**
 * @author Zane
 */
public class ConfigEditFragment extends Fragment {
    private Boolean editable;
    private Boolean virtualKeyboardConfigMode;
    private String configPath;

    private FragmentConfigEditBinding binding;

    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        binding = FragmentConfigEditBinding.inflate(inflater, container, false);
        initView();
        binding.buttonConfigCancel.setOnClickListener(v -> onConfigCancel());
        binding.buttonConfigSave.setOnClickListener(v -> onConfigSave());
        binding.buttonLogParser.setOnClickListener(v -> onLogParser());
        return binding.getRoot();
    }

    private void initView() {
        CommonLogic.doOnNonNull(this.getArguments(), arguments -> {
            ConfigEditFragmentArgs args = ConfigEditFragmentArgs.fromBundle(arguments);
            editable = args.getEditable();
            virtualKeyboardConfigMode = args.getVirtualKeyboardConfigMode();
            if (!editable) {
                binding.buttonConfigSave.setVisibility(View.INVISIBLE);
                binding.buttonConfigCancel.setVisibility(View.INVISIBLE);
                binding.buttonLogParser.setVisibility(View.VISIBLE);
            }
            configPath = args.getConfigPath();
            File file = new File(configPath);
            if (file.exists() && file.length() < Constants.TEXT_FILE_OPEN_SIZE_LIMIT) {
                initAssetWebView();
                binding.scrollView.post(() -> CommonLogic.doOnNonNull(this.getContext(), (context -> onScrollViewRendered(file, context))));
            } else {
                DialogUtils.showConfirmDialog(binding.getRoot(), R.string.error, this.getString(R.string.text_too_large), R.string.open_with, R.string.cancel, ((dialog, which) -> {
                    if (which == DialogAction.POSITIVE) {
                        Intent intent = new Intent("android.intent.action.VIEW");
                        intent.addCategory("android.intent.category.DEFAULT");
                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);