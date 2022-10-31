package com.zane.smapiinstaller.ui.download;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import com.lmntrx.android.library.livin.missme.ProgressDialog;
import com.lzy.okgo.OkGo;
import com.lzy.okgo.callback.FileCallback;
import com.lzy.okgo.model.Progress;
import com.lzy.okgo.model.Response;
import com.microsoft.appcenter.crashes.Crashes;
import com.zane.smapiinstaller.R;
import com.zane.smapiinstaller.constant.DialogAction;
import com.zane.smapiinstaller.constant.DownloadableContentTypeConstants;
import com.zane.smapiinstaller.databinding.DownloadContentItemBinding;
import com.zane.smapiinstaller.entity.DownloadableContent;
import com.zane.smapiinstaller.entity.ModManifestEntry;
import com.zane.smapiinstaller.logic.ModAssetsManager;
import com.zane.smapiinstaller.utils.DialogUtil