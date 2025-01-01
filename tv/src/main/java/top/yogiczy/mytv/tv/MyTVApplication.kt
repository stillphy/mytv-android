package top.yogiczy.mytv.tv

import android.app.Application
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import coil.ImageLoader
import coil.ImageLoaderFactory
import coil.decode.SvgDecoder
import coil.disk.DiskCache
import coil.memory.MemoryCache
import coil.request.CachePolicy
import coil.util.DebugLogger
import io.sentry.Hint
import io.sentry.Sentry
import io.sentry.SentryEvent
import io.sentry.SentryLevel
import io.sentry.SentryOptions
import io.sentry.android.core.SentryAndroid
import top.yogiczy.mytv.core.data.AppData
import top.yogiczy.mytv.core.data.utils.Globals
import top.yogiczy.mytv.tv.ui.utils.Configs
import kotlin.system.exitProcess

class MyTVApplication : Application(), ImageLoaderFactory {
    override fun onCreate() {
        super.onCreate()
        // 获取 Android ID
        Globals.androidIdStr = getAndroidId()
        Globals.androidVersion = getAppVersion().toString()
        Configs.appLastLatestVersion=Globals.androidVersion
        initSentry()
        crashHandle()
        AppData.init(applicationContext)
        UnsafeTrustManager.enableUnsafeTrustManager()
    }
    private fun getAndroidId(): String {
        return android.provider.Settings.Secure.getString(contentResolver, android.provider.Settings.Secure.ANDROID_ID)
    }
    private fun getAppVersion(): String? {
        try {
            val packageInfo: PackageInfo =
                packageManager.getPackageInfo(packageName,  0)
            return packageInfo.versionName
        } catch (e: PackageManager.NameNotFoundException) {            
            return ""
        }
    }
    override fun newImageLoader(): ImageLoader {
        return ImageLoader(this).newBuilder()
            .logger(DebugLogger())
            .components {
                add(SvgDecoder.Factory())
            }
            .crossfade(true)
            .memoryCachePolicy(CachePolicy.ENABLED)
            .memoryCache {
                MemoryCache.Builder(this)
                    // .maxSizePercent(0.25)
                    .build()
            }
            .diskCachePolicy(CachePolicy.ENABLED)
            .diskCache {
                DiskCache.Builder()
                    .directory(cacheDir.resolve("image_cache"))
                    // .maxSizeBytes(1024 * 1024 * 100)
                    .build()
            }
            .build()
    }

    private fun initSentry() {
        SentryAndroid.init(this) { options ->
            options.environment = BuildConfig.BUILD_TYPE
            options.dsn = BuildConfig.SENTRY_DSN
            options.tracesSampleRate = 1.0
            options.beforeSend =
                SentryOptions.BeforeSendCallback { event: SentryEvent, _: Hint ->
                    if (event.level == null) event.level = SentryLevel.FATAL

                    if (BuildConfig.DEBUG) return@BeforeSendCallback null
                    if (SentryLevel.ERROR != event.level && SentryLevel.FATAL != event.level) return@BeforeSendCallback null
                    if (event.exceptions?.any { ex -> ex.type?.contains("Http") == true } == true) return@BeforeSendCallback null

                    event
                }
        }

        @Suppress("UnstableApiUsage")
        Sentry.withScope { scope ->
            Globals.deviceId = scope.options.distinctId ?: ""
        }
    }

    private fun crashHandle() {
        Thread.setDefaultUncaughtExceptionHandler { _, throwable ->
            throwable.printStackTrace()
            Sentry.captureException(throwable)

            val intent = Intent(this, CrashHandlerActivity::class.java).apply {
                putExtra("error_message", throwable.message)
                putExtra("error_stacktrace", throwable.stackTraceToString())
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            }
            startActivity(intent)

            android.os.Process.killProcess(android.os.Process.myPid())
            exitProcess(1)
        }
    }
}
