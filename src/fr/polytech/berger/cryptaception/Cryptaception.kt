package fr.polytech.berger.cryptaception

import java.math.BigInteger
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.util.*

class Cryptaception(
	private var _publicKey: Pair<BigInteger, BigInteger>,
	private var _secretKey: BigInteger
): Observable() {
	
	//region STATIC CONTEXT
	
	companion object {
		const val DEFAULT_KEY_SIZE_BITS = 512
		
		fun randomCryptaception(keySizeBits: Int = DEFAULT_KEY_SIZE_BITS): Cryptaception {
			val p = PrimeManager.generateRandomPrimeNumber(keySizeBits)
			val q = PrimeManager.generateRandomPrimeNumber(keySizeBits)
			
			val n = p.multiply(q)
			val phi_n = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE))
			
			var e = BigInteger.ZERO
			while (e.gcd(phi_n) != BigInteger.ONE)
				e = PrimeManager.generateRandomPrimeNumber(16)
			
			val d = e.modInverse(phi_n)
			
			// Assert that e * d mod Φ_n = 1
			assert(BigInteger.ONE == e.multiply(d).mod(phi_n))
			
			val publicKey = Pair<BigInteger, BigInteger>(n, e)
			val privateKey = d
			
			return Cryptaception(publicKey, privateKey)
		}
	}
	
	//endregion
	
	//region PROPERTIES
	
	var publicKey: Pair<BigInteger, BigInteger>
		get() = _publicKey
		set(value) {
			_publicKey = value
			notifyObservers()
		}
	
	var secretKey: BigInteger
		get() = _secretKey
		set(value) { _secretKey = value }
	
	//endregion
	
	//region METHODS
	
	fun encrypt(bigInteger: BigInteger): BigInteger {
		return bigInteger.modPow(
			publicKey.second,
			publicKey.first
		)
	}
	fun encrypt(value: Number): BigInteger {
		return encrypt(BigInteger(value.toString()))
	}
	fun encrypt(value: ByteArray): BigInteger {
		return encrypt(BigInteger(value))
	}
	fun encrypt(value: String, charset: Charset = StandardCharsets.UTF_8): BigInteger {
		return encrypt(value.toByteArray(StandardCharsets.UTF_8))
	}
	
	fun decryptToBigInteger(encryptedBigInteger: BigInteger): BigInteger {
		return encryptedBigInteger.modPow(
			secretKey,
			publicKey.first
		)
	}
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
	
	//endregion
}
