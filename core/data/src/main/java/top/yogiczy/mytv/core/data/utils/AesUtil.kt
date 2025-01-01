package top.yogiczy.mytv.core.data.utils

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

class AesUtil(
    private val sig: String = "12315",
    private val appname: String = "mytv",
    private val packagename: String = "com.mytv",
    private val method: String = "AES/ECB/PKCS5Padding"
) {

    private val secretKey: SecretKeySpec
    private val cipher: Cipher

    init {
        // 生成密钥
        val key = (sig + appname + packagename + "AD80F93B542B")
        // 截取16字节的子字符串作为密钥，以符合AES-128要求
        val processedKey = key.substring(0, 16).toByteArray(Charsets.UTF_8)
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
