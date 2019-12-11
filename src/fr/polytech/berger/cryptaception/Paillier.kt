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
		
		// n = pq
		val n = p.multiply(q)
		// phi(n) = (p - 1)(q - 1)
		val phi_n = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE))
		// rho = n^(-1) mod phi(n)
		val rho = n.modInverse(phi_n)
		
		val publicKey = n
		val privateKey = rho
		
		return Pair<BigInteger, BigInteger>(publicKey, privateKey)
	}
	fun keyGen(): Pair<BigInteger, BigInteger> {
		return keyGen(DEFAULT_KEY_SIZE_BITS)
	}
	
	override fun encrypt(bigInteger: BigInteger): BigInteger {
		// r = random(0, n-1)
		val r = BigInteger(publicKey.bitLength(), Random()).mod(publicKey)
		// M = (1 + m * n) * r^n mod n²
		val M = (BigInteger.ONE.plus(bigInteger.multiply(publicKey))).multiply(r.modPow(publicKey, publicKey.pow(2)))
		return M
	}
	
	override fun decryptToBigInteger(encryptedBigInteger: BigInteger): BigInteger {
		// r = (M mod n)^rho
		val r = encryptedBigInteger.modPow(secretKey, publicKey)
		// m = ((M * r^(-n) mod n²) - 1)/n
		val m = (encryptedBigInteger.multiply(r.modPow(publicKey, publicKey.pow(2)).modInverse(publicKey.pow(2))))
			.mod(publicKey.pow(2)).subtract(BigInteger.ONE).divide(publicKey)
		return m
	}
	
	//endregion
}