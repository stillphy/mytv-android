package top.yogiczy.mytv.core.data.repositories.git.parser

import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import top.yogiczy.mytv.core.data.entities.git.GitRelease
import top.yogiczy.mytv.core.data.utils.Globals

/**
 * 缺省发行版解析
 */
class DefaultGitReleaseParser : GitReleaseParser {
    override fun isSupport(url: String): Boolean {
        return true
    }

    override suspend fun parse(data: String): GitRelease {
        //return GitRelease(
        //    version = "0.0.0",
        //    downloadUrl = "",
        //    description = "不支持当前链接",
        //)
        val json = Globals.json.parseToJsonElement(data).jsonObject

        return GitRelease(
            version = json.getValue("tag_name").jsonPrimitive.content.substring(1),
            downloadUrl = json.getValue("assets").jsonArray[0].jsonObject["browser_download_url"]!!.jsonPrimitive.content,
            description = json.getValue("body").jsonPrimitive.content,
        )
    }
}