package top.yogiczy.mytv.tv.ui.utils

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import top.yogiczy.mytv.core.data.entities.channel.Channel
import top.yogiczy.mytv.core.data.entities.epgsource.EpgSource
import top.yogiczy.mytv.core.data.entities.epgsource.EpgSourceList
import top.yogiczy.mytv.core.data.entities.iptvsource.IptvSource
import top.yogiczy.mytv.core.data.entities.iptvsource.IptvSourceList
import top.yogiczy.mytv.core.data.network.request
import top.yogiczy.mytv.core.data.utils.Constants
import top.yogiczy.mytv.core.data.utils.Globals
import java.lang.Exception
import android.os.Build
import top.yogiczy.mytv.core.data.utils.AesUtil
import top.yogiczy.mytv.core.data.utils.Logger
import top.yogiczy.mytv.core.data.utils.md5

val log = Logger.create("GetRemoteConfigUtil")
object GetRemoteConfigUtil {

    @Serializable
    data class RemoteConfigData(
        var appBootLaunch: Boolean=Configs.appBootLaunch,
        var appPipEnable: Boolean=Configs.appPipEnable,
        var appAgreementAgreed: Boolean=false,
        var appStartupScreen: String="Dashboard",
        var iptvSourceList: IptvSourceList=Configs.iptvSourceList,
        var iptvSourceCurrent: IptvSource= Constants.IPTV_SOURCE_LIST.first(),
        var iptvChannelLastPlay: Channel=Channel(),
        var iptvSourceCacheTime: Long=Configs.iptvSourceCacheTime,
        var epgEnable: Boolean = Configs.epgEnable,
        var epgSourceCurrent: EpgSource=Configs.epgSourceCurrent,
        var epgSourceList: EpgSourceList=Configs.epgSourceList,
        var epgRefreshTimeThreshold: Int=Configs.epgRefreshTimeThreshold,
        var uiUseClassicPanelScreen: Boolean=Configs.uiUseClassicPanelScreen,

        var updateForceRemind: Boolean=Configs.updateForceRemind,
        var updateChannel: String = Configs.updateChannel,
        var updateUrl:String ="",
        var remoteEncryptKey:String = Globals.androidIdStr,
        var remoteEncryptEnable:Boolean = false,
        // 添加其他需要同步的字段 
    )

    @Serializable
    data class PostInfoData(
        val deviceBrand:String,
        val deviceName: String,
        val deviceOsVer:String,
        val deviceMac:String,
        var sdkVer:Int,
        val androidId: String,
        val apkAppName: String,
        val apkPackageName: String,
        val apkVer: String,
        var t: Long,
        var sign:String,
    )

    @Serializable
    data class ConfigResponse(
        var code: Int,
        var msg: String,
        var data: RemoteConfigData,
    )


    suspend fun postSettingsToCloud(
        url: String
    ): ConfigResponse {
        val timestampLong=System.currentTimeMillis()  / 1000
        // 先计算签名
        val signStr = "${Build.BRAND}${Globals.deviceName}${Build.VERSION.RELEASE}${Globals.deviceMac}${Build.VERSION.SDK_INT}${Globals.androidIdStr}${Globals.apkAppName}${Globals.apkPackageName}${Globals.apkVersion}$timestampLong"
        val sign = signStr.md5()
        // 发送信息 
        val postInfo = PostInfoData(
            deviceBrand = Build.BRAND,
            deviceName = Globals.deviceName,
            deviceOsVer = Build.VERSION.RELEASE,
            deviceMac=Globals.deviceMac,
            sdkVer = Build.VERSION.SDK_INT,
            androidId = Globals.androidIdStr,
            apkAppName= Globals.apkAppName,
            apkPackageName = Globals.apkPackageName,
            apkVer = Globals.apkVersion,
            t=timestampLong,
            sign = sign,
        )

        val jsonPayload = Json.encodeToString(postInfo)
        return okPostEx(url, jsonPayload)
    }
}

fun parseResponse(responseBody: String): GetRemoteConfigUtil.ConfigResponse {
    val json = Json { ignoreUnknownKeys = true }
    return try {
        json.decodeFromString(responseBody)
    } catch (e: Exception) {
        throw Exception("Failed to parse response: ${e.message}")
    }
}

val jsonMediaType = "application/json; charset=utf-8".toMediaType()


suspend fun okPostEx(url: String, jsonPayload: String): GetRemoteConfigUtil.ConfigResponse {
    return url.request(
        builder = {
            it.post(jsonPayload.toRequestBody(jsonMediaType))
        },
        action = { response, _ ->
            var responseBody = response.body?.string()?:  throw Exception("Empty response")
            val aes=AesUtil(Globals.androidIdStr,Globals.apkAppName,Globals.apkPackageName)
            try {
                responseBody = aes.decrypt(responseBody)
            }catch (ex: Exception){
                log.e("解密远程配置失败" )
            }
            val configResponse = parseResponse(responseBody)
            if (configResponse.code  == 200) {
                // 在这里可以添加对configResponse.data （即RemoteConfigData）的处理逻辑 
                // 例如将相关数据存储到本地设置等操作 
                // 这里只是简单打印一下数据示例
                //val data = configResponse.data
                //怎么判断有没有data.appAgreementAgreed这个数据,如果appAgreementAgreed不存在这项呢？怎么处理
                //Configs.appAgreementAgreed = data.appAgreementAgreed
                configResponse.data?.let { data ->
                    //设置到存储配置
                    Configs.appBootLaunch = data.appBootLaunch
                    Configs.appPipEnable = data.appPipEnable
                    Configs.appAgreementAgreed = data.appAgreementAgreed
                    Configs.appStartupScreen = data.appStartupScreen
                    Configs.iptvSourceCurrent = data.iptvSourceCurrent

                    if(Configs.lastIptvSourceName != data.iptvSourceCurrent.name){
                        Configs.iptvChannelLastPlay = data.iptvChannelLastPlay
                        Configs.lastIptvSourceName=data.iptvSourceCurrent.name
                    }

                    Configs.iptvSourceCacheTime = data.iptvSourceCacheTime
                    Configs.epgEnable = data.epgEnable
                    Configs.epgSourceCurrent = data.epgSourceCurrent
                    Configs.epgSourceList = data.epgSourceList
                    Configs.epgRefreshTimeThreshold = data.epgRefreshTimeThreshold
                    Configs.uiUseClassicPanelScreen = data.uiUseClassicPanelScreen

                    Configs.updateForceRemind = data.updateForceRemind
                    Configs.updateChannel = data.updateChannel
                    Configs.updateUrl = data.updateUrl
                    //设置到临时全局变量
                    Globals.remoteEncryptEnable=data.remoteEncryptEnable
                    Globals.remoteEncryptKey=data.remoteEncryptKey
                }

            }
            configResponse
        }
    )
}
