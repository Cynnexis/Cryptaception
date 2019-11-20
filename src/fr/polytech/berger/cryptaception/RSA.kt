package fr.polytech.berger.cryptaception

import java.math.BigInteger

class RSA(
	private var _publicKey: Pair<BigInteger, BigInteger>,
	private var _secretKey: BigInteger
): Cryptaception<Pair<BigInteger, BigInteger>, BigInteger>(_publicKey, _secretKey) {
	//region STATIC CONTEXT
	
	companion object {
		fun randomCryptaception(keySizeBits: Int = DEFAULT_KEY_SIZE_BITS): RSA {
			val rsa = RSA(Pair(BigInteger.ZERO, BigInteger.ZERO), BigInteger.ZERO)
			val bunch = rsa.keyGen(keySizeBits)
			
			return RSA(bunch.first, bunch.second)
		}
	}
	
	//endregion
	
	//region METHODS
	
	override fun keyGen(keySizeBits: Int): Pair<Pair<BigInteger, BigInteger>, BigInteger> {
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
		
		return Pair<Pair<BigInteger, BigInteger>, BigInteger>(publicKey, privateKey)
	}
	fun keyGen(): Pair<Pair<BigInteger, BigInteger>, BigInteger> {
		return keyGen(DEFAULT_KEY_SIZE_BITS)
	}
	
	override fun encrypt(bigInteger: BigInteger): BigInteger {
		return bigInteger.modPow(
			publicKey.second,
			publicKey.first
		)
	}
	
	override fun decryptToBigInteger(encryptedBigInteger: BigInteger): BigInteger {
		return encryptedBigInteger.modPow(
			secretKey,
			publicKey.first
		)
	}
	
	//endregion
}