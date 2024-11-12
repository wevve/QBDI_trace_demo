package cn.mrack.xposed.nhook;

import android.app.Activity;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.util.Log;

public class SettingsActivity extends Activity {

    static {
        System.loadLibrary("nhook");
    }

    public static class SettingsFragment extends PreferenceFragment {
        @Override
        public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            addPreferencesFromResource(R.xml.settings);
            Preference moduleStatus = findPreference("module_status");
            boolean active = isModuleActive();
            Log.d("MainHook", "onCreate: " + active);
            moduleStatus.setEnabled(active);
            moduleStatus.setTitle(active ? "模块状态: [已激活]" : "模块状态: [未激活]");
           HookUtils.nativeHookInit(getContext());

            String sajdlaskkjdlaks = NHook.sign1("sajdlaskkjdlaks");
            Log.d("MainHook", "onCreate: " + sajdlaskkjdlaks);

            Runtime rt=Runtime.getRuntime();
            long maxMemory=rt.maxMemory();
            Log.d("MainHook","当前最大内存空间 "+Long.toString(maxMemory/(1024*1024)));


        }
    }

    private static final String TAG = "SettingsActivity";
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getFragmentManager().beginTransaction().replace(android.R.id.content, new SettingsFragment()).commit();
    }

    public static boolean isModuleActive() {
        return false;
    }
}
