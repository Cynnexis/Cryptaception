package fr.polytech.berger.cryptaception

import java.math.BigInteger
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets

/**
 * Interface for crypto-system.
 * @param PK The primary key type.
 * @param SK The secret key type.
 */
interface ICrypt<PK, SK> {
	
	/**
	 * Generate public and secret keys.
	 * @param keySizeBits The size of the keys in bits.
	 * @return The size
	 */
	fun keyGen(keySizeBits: Int = Cryptaception.DEFAULT_KEY_SIZE_BITS): Pair<PK, SK>
	
	fun encrypt(bigInteger: BigInteger): BigInteger
	fun encrypt(value: Number): BigInteger {
		return encrypt(BigInteger(value.toString()))
	}
	fun encrypt(value: ByteArray): BigInteger {
		return encrypt(BigInteger(value))
	}
	fun encrypt(value: String, charset: Charset = StandardCharsets.UTF_8): BigInteger {
		return encrypt(value.toByteArray(StandardCharsets.UTF_8))
	}
	
	fun decryptToBigInteger(encryptedBigInteger: BigInteger): BigInteger
	fun decryptToShort(encryptedBigInteger: BigInteger): Short {
		return decryptToBigInteger(encryptedBigInteger).toShort()
	}
	fun decryptToInt(encryptedBigInteger: BigInteger): Int {
		return decryptToBigInteger(encryptedBigInteger).toInt()
	}
	fun decryptToChar(encryptedBigInteger: BigInteger): Char {
		return decryptToBigInteger(encryptedBigInteger).toChar()
	}
	fun decryptToByte(encryptedBigInteger: BigInteger): Byte {
		return decryptToBigInteger(encryptedBigInteger).toByte()
	}
	fun decryptToFloat(encryptedBigInteger: BigInteger): Float {
		return decryptToBigInteger(encryptedBigInteger).toFloat()
	}
	fun decryptToDouble(encryptedBigInteger: BigInteger): Double {
		return decryptToBigInteger(encryptedBigInteger).toDouble()
	}
	fun decryptToByteArray(encryptedBigInteger: BigInteger): ByteArray {
		return decryptToBigInteger(encryptedBigInteger).toByteArray()
	}
	fun decryptToString(encryptedBigInteger: BigInteger, charset: Charset = StandardCharsets.UTF_8): String {
		return String(decryptToByteArray(encryptedBigInteger), charset)
	}
}