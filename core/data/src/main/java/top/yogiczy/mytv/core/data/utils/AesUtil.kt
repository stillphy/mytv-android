package top.yogiczy.mytv.core.data.utils

import android.annotation.SuppressLint
import android.os.Build
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

@OptIn(ExperimentalStdlibApi::class)
fun String.md5(): String {
    val md = MessageDigest.getInstance("MD5")
    val digest = md.digest(this.toByteArray())
    return digest.toHexString()
}
val log = Logger.create("AesUtil")
@SuppressLint("GetInstance")
class AesUtil(
    private val sig: String = "12315",
    private val appName: String = "mytv",
    private val packageName: String = "com.mytv",
    private val method: String = "AES/ECB/PKCS5Padding"
) {

    private val secretKey: SecretKeySpec
    private val cipher: Cipher

    init {
        // 生成密钥
        val key = (sig + appName + packageName + "AD80F93B542B")
        var md5Str=key.md5()
        md5Str=(md5Str+appName + packageName).md5()
        // 截取16字节的子字符串作为密钥，以符合AES-128要求
        val processedKey = md5Str.substring(0, 16).toByteArray(Charsets.UTF_8)

        secretKey = SecretKeySpec(processedKey, "AES")
        cipher = Cipher.getInstance(method)
    }

    fun encrypt(data: String): String {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedBytes = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }

    fun decrypt(data: String): String {
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        val decodedBytes = Base64.getDecoder().decode(data)
        val decryptedBytes = cipher.doFinal(decodedBytes)
        return String(decryptedBytes, Charsets.UTF_8)
    }
}
