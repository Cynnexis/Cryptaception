package fr.polytech.berger.cryptaception

import java.math.BigInteger
import java.util.*

class Paillier(
	private var _publicKey: BigInteger,
	private var _secretKey: BigInteger
): Cryptaception<BigInteger, BigInteger>(_publicKey, _secretKey) {
	
	//region STATIC CONTEXT
	
	companion object {
		fun randomCryptaception(keySizeBits: Int = DEFAULT_KEY_SIZE_BITS): Paillier {
			val paillier = Paillier(BigInteger.ZERO, BigInteger.ZERO)
			val bunch = paillier.keyGen(keySizeBits)
			
			return Paillier(bunch.first, bunch.second)
		}
	}
	
	//endregion
	
	//region METHODS
	
	override fun keyGen(keySizeBits: Int): Pair<BigInteger, BigInteger> {
		val p = PrimeManager.generateRandomPrimeNumber(keySizeBits)
		val q = PrimeManager.generateRandomPrimeNumber(keySizeBits)
		
		val n = p.multiply(q)
		val phi_n = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE))
		val rho = n.modInverse(phi_n)
		
		val publicKey = n
		val privateKey = rho
		
		return Pair<BigInteger, BigInteger>(publicKey, privateKey)
	}
	
	override fun encrypt(bigInteger: BigInteger): BigInteger {
		val r = BigInteger(publicKey.bitLength(), Random()).mod(publicKey)
		val M = (BigInteger.ONE.plus(bigInteger.multiply(publicKey))).multiply(r.modPow(publicKey, publicKey.pow(2)))
		return M
	}
	
	override fun decryptToBigInteger(encryptedBigInteger: BigInteger): BigInteger {
		val r = encryptedBigInteger.modPow(secretKey, publicKey)
		val m = (encryptedBigInteger.multiply(r.modPow(publicKey, publicKey.pow(2)).modInverse(publicKey.pow(2))))
			.mod(publicKey.pow(2)).subtract(BigInteger.ONE).divide(publicKey)
		return m
	}
	
	//endregion
}