package top.yogiczy.mytv.tv.ui.utils

import android.annotation.SuppressLint
import android.content.Context
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import java.io.BufferedReader
import java.io.FileReader
import java.io.IOException
import java.net.NetworkInterface
import java.util.Collections
import java.util.Locale

/**
 * 获取MAC地址
 *
 * @param context
 * @return
 */
fun getMacAddress(context: Context?): String {
    return when {
        Build.VERSION.SDK_INT < Build.VERSION_CODES.M -> {
            getMacDefault(context)
        }
        Build.VERSION.SDK_INT < Build.VERSION_CODES.N -> {
            getMacAddressM()
        }
        else -> {
            getMacFromHardware()
        }
    }
}

/**
 * Android  6.0 之前（不包括6.0）
 *
 * @param context
 * @return
 */
@SuppressLint("HardwareIds")
private fun getMacDefault(context: Context?): String {
    var mac = "未获取到设备Mac地址"
    if (context == null) return mac

    val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    var info: WifiInfo? = null
    try {
        info = wifi.connectionInfo
    } catch (e: Exception) {
        e.printStackTrace()
    }
    if (info == null) return mac
    mac = info.macAddress

    if (mac.isNotEmpty()) mac = mac.uppercase(Locale.ENGLISH)

    return mac
}

/**
 * Android 6.0（包括） - Android 7.0（不包括）
 *
 * @return
 */
private fun getMacAddressM(): String {
    var mac = "未获取到设备Mac地址"

    try {
        mac = BufferedReader(FileReader("/sys/class/net/wlan0/address")).readLine()
    } catch (e: IOException) {
        e.printStackTrace()
    }

    return mac
}

/**
 * 遍历循环所有的网络接口，找到接口是 wlan0
 *
 * @return
 */
private fun getMacFromHardware(): String {
    try {
        val all: List<NetworkInterface> =
            Collections.list(NetworkInterface.getNetworkInterfaces())

        for (nif in all) {
            if (!nif.name.equals("wlan0", ignoreCase = true)) continue

            val macBytes = nif.hardwareAddress ?: return ""

            val res1 = StringBuilder()
            for (b in macBytes) {
                res1.append(String.format("%02X:", b))
            }

            if (res1.isNotEmpty()) {
                res1.deleteCharAt(res1.length - 1)
            }
            return res1.toString()
        }
    } catch (e: Exception) {
        e.printStackTrace()
    }
    return "未获取到设备Mac地址"
}