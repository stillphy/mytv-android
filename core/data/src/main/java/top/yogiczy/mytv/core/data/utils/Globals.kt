package top.yogiczy.mytv.core.data.utils

import android.content.res.Resources
import kotlinx.serialization.json.Json
import java.io.File

/**
 * 全局变量
 */
object Globals {
    lateinit var cacheDir: File

    lateinit var fileDir: File

    lateinit var resources: Resources

    lateinit var deviceName: String
    var deviceId: String = "Unknown"

    var deviceMac: String =""
    var androidIdStr: String =""
    var apkAppName:String =""
    var apkPackageName:String =""
    var apkVersion: String =""
    var enableRemoteConfig: Boolean = true
    var remoteConfigUrl: String ="http://127.0.0.1:20243/app/m3utotxt/getconf.php"
    var remoteEncryptKey:String=""
    var remoteEncryptEnable:Boolean=false

    val json = Json {
        encodeDefaults = true
        explicitNulls = true
        ignoreUnknownKeys = true
        coerceInputValues = true
    }
}