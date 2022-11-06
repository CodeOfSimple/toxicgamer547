package com.zane.smapiinstaller.ui.main;

import android.os.Bundle;

import com.zane.smapiinstaller.R;
import com.zane.smapiinstaller.ui.about.AboutFragment;
import com.zane.smapiinstaller.ui.config.ConfigFragment;
import com.zane.smapiinstaller.ui.download.DownloadableContentFragment;
import com.zane.smapiinstaller.ui.help.HelpFragment;
import com.zane.smapiinstaller.ui.install.InstallFragment;

import org.jetbrains.annotations.NotNull;

import androidx.fragment.app.Fragment;
import androidx.viewpager2.adapter.FragmentStateAdapter;

class MainTabPagerAdapter extends FragmentStateAdapter {
    private final Fragment fragment;

    public MainTabPagerAdapter(Fragment fragment) {
        super(fragment);
        this.fragment = fragment;
    }

    @NotNull
    @Override
    public Fragment createFragment(int position) {
        Bundle args = new Bundle();
        Fragment fragment;
        switch (position){
            case 1:
                fragment = new ConfigFragment();
                fragment.setArguments(args);
                return fragment;
            case 2:
                fragment = new DownloadableContentFragment();
                fragment.setArguments(args);
                return fragment;
            case 3:
                fragment = new HelpFragment();
                fragment.setArguments(args);
                retur