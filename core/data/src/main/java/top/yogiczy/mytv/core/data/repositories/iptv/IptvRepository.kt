package top.yogiczy.mytv.core.data.repositories.iptv

import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import top.yogiczy.mytv.core.data.entities.channel.ChannelGroupList
import top.yogiczy.mytv.core.data.entities.iptvsource.IptvSource
import top.yogiczy.mytv.core.data.network.HttpException
import top.yogiczy.mytv.core.data.network.request
import top.yogiczy.mytv.core.data.repositories.FileCacheRepository
import top.yogiczy.mytv.core.data.repositories.iptv.parser.IptvParser
import top.yogiczy.mytv.core.data.repositories.iptv.parser.IptvParser.ChannelItem.Companion.toChannelGroupList
import top.yogiczy.mytv.core.data.utils.AesUtil
import top.yogiczy.mytv.core.data.utils.Globals
import top.yogiczy.mytv.core.data.utils.Logger
import kotlin.time.measureTimedValue

/**
 * 直播源数据获取
 */
class IptvRepository(private val source: IptvSource) :
    FileCacheRepository(source.cacheFileName("json")) {

    private val log = Logger.create("IptvRepository")
    private val rawRepository = IptvRawRepository(source)

    private fun isExpired(lastModified: Long, cacheTime: Long): Boolean {
        val timeout =
            System.currentTimeMillis() - lastModified >= (if (source.isLocal) Long.MAX_VALUE else cacheTime)
        val rawChanged = lastModified < rawRepository.lastModified()

        return timeout || rawChanged
    }

    private suspend fun refresh(
        transform: suspend ((List<IptvParser.ChannelItem>) -> List<IptvParser.ChannelItem>) = { it -> it },
    ): String {
        val raw = rawRepository.getRaw()
        val parser = IptvParser.instances.first { it.isSupport(source.url, raw) }

        log.d("开始解析直播源（${source.name}）...")
        return measureTimedValue {
            val list = parser.parse(raw)
            Globals.json.encodeToString(withContext(Dispatchers.Default) {
                runCatching { transform(list) }
                    .getOrDefault(list)
                    .toChannelGroupList()
            })
        }.let {
            log.i("解析直播源（${source.name}）完成", null, it.duration)
            it.value
        }
    }

    private suspend fun transform(channelList: List<IptvParser.ChannelItem>): List<IptvParser.ChannelItem> =
        withContext(Dispatchers.IO) {
            if (source.transformJs.isNullOrBlank()) return@withContext channelList

            val context = org.mozilla.javascript.Context.enter()
            context.optimizationLevel = -1
            val result = runCatching {
                val scope = context.initStandardObjects()
                context.evaluateString(
                    scope, """
                    (function() {
                        var channelList = ${Globals.json.encodeToString(channelList)};
                        ${source.transformJs}
                        return JSON.stringify(main(channelList));
                    })();
                    """.trimIndent(), "JavaScript", 1, null
                ) as String
            }
            org.mozilla.javascript.Context.exit()

            if (result.isFailure) {
                log.e("转换直播源（${source.name}）错误: ${result.exceptionOrNull()}")
            }

            if (result.isSuccess) Globals.json.decodeFromString(result.getOrNull()!!)
            else channelList
        }

    /**
     * 获取直播源分组列表
     */
    suspend fun getChannelGroupList(cacheTime: Long): ChannelGroupList {
        try {
            val json = getOrRefresh({ lastModified, _ -> isExpired(lastModified, cacheTime) }) {
                refresh { transform(it) }
            }

            return Globals.json.decodeFromString<ChannelGroupList>(json).also { groupList ->
                log.i("加载直播源（${source.name}）：${groupList.size}个分组，${groupList.sumOf { it.channelList.size }}个频道")
            }
        } catch (ex: Exception) {
            log.e("加载直播源（${source.name}）失败", ex)
            throw ex
        }
    }

    suspend fun getEpgUrl(): String? {
        return runCatching {
            val sourceData = rawRepository.getRaw(Long.MAX_VALUE)
            val parser = IptvParser.instances.first { it.isSupport(source.url, sourceData) }
            parser.getEpgUrl(sourceData)
        }.getOrNull()
    }

    override suspend fun clearCache() {
        rawRepository.clearCache()
        super.clearCache()
    }

    companion object {
        suspend fun clearAllCache() = withContext(Dispatchers.IO) {
            IptvSource.cacheDir.deleteRecursively()
        }
    }
}

private class IptvRawRepository(private val source: IptvSource) : FileCacheRepository(
    if (source.isLocal) source.url else source.cacheFileName("txt"),
    source.isLocal,
) {

    private val log = Logger.create("IptvRawRepository")

    suspend fun getRaw(cacheTime: Long = 0): String {
        return getOrRefresh(if (source.isLocal) Long.MAX_VALUE else cacheTime) {
            log.d("获取直播源: $source")

            try {
/*
                // 假设 source.url 是一个 URL 对象
                val androidId = Globals.androidIdStr
                // 获取当前 URL 的字符串表示
                val originalUrl = source.url.toString()

                // 进行 URL 编码Uri需要引入import android.net.Uri
                val encodedAndroidId = Uri.encode(androidId)

                // 检查原始 URL 是否已包含查询参数
                val newUrl = if (originalUrl.contains("?")) {
                    // 使用 & 添加新参数
                    "$originalUrl&androidId=$encodedAndroidId"
                } else {
                    // 使用 ? 添加新参数
                    "$originalUrl?androidId=$encodedAndroidId"
                }
                //log.d("newUrl: $newUrl")
*/
                // 假设 source.url 是一个 URL 对象
                val androidId = Globals.androidIdStr
                val newUrl =  if (source.url.contains("{androidid}")){
                    source.url.replace("{androidid}",  androidId)
                }else{
                    source.url
                }
                // 进行请求
                val bodyString= newUrl.request { body -> body.string() } ?: ""
                if(Globals.iptvSourcesEncrypt){
                    val aes=AesUtil()
                    aes.decrypt(bodyString)
                }else
                    bodyString
                //source.url.request { body -> body.string() } ?: ""
            } catch (ex: Exception) {
                log.e("获取直播源（${source.name}）失败", ex)
                throw HttpException("获取直播源失败，请检查网络连接", ex)
            }
        }
    }

    override suspend fun clearCache() {
        if (source.isLocal) return
        super.clearCache()
    }
}