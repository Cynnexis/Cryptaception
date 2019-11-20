package fr.polytech.berger.cryptaception

import org.junit.jupiter.api.BeforeEach

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.math.BigInteger

internal class CryptaceptionTest {
	
	@Test
	fun encryptDecryptRSAString() {
		encryptDecrypt<String, Pair<BigInteger, BigInteger>, BigInteger>(
			"Hello world",
			{ x -> x },
			{ keySizeBits -> RSA.randomCryptaception(keySizeBits) },
			{ crypta, message -> crypta.encrypt(message) },
			{ crypta, encryptedMessage -> crypta.decryptToString(encryptedMessage) }
		)
	}
	
	@Test
	fun encryptDecryptRSAInt() {
		encryptDecrypt<Int, Pair<BigInteger, BigInteger>, BigInteger>(
			42,
			{ x -> x.toString() },
			{ keySizeBits -> RSA.randomCryptaception(keySizeBits) },
			{ crypta, message -> crypta.encrypt(message) },
			{ crypta, encryptedMessage -> crypta.decryptToInt(encryptedMessage) }
		)
	}
	
	@Test
	fun encryptDecryptPaillierString() {
		encryptDecrypt<String, BigInteger, BigInteger>(
			"Hello world",
			{ x -> x },
			{ keySizeBits -> Paillier.randomCryptaception(keySizeBits) },
			{ crypta, message -> crypta.encrypt(message) },
			{ crypta, encryptedMessage -> crypta.decryptToString(encryptedMessage) }
		)
	}
	
	@Test
	fun encryptDecryptPaillierInt() {
		encryptDecrypt<Int, BigInteger, BigInteger>(
			42,
			{ x -> x.toString() },
			{ keySizeBits -> Paillier.randomCryptaception(keySizeBits) },
			{ crypta, message -> crypta.encrypt(message) },
			{ crypta, encryptedMessage -> crypta.decryptToInt(encryptedMessage) }
		)
	}
	
	private fun <T, PK, SK> encryptDecrypt(value: T,
			                       typeToString: (T) -> String,
	                               keyGen: (Int) -> Cryptaception<PK, SK>,
			                       encrypt: (Cryptaception<PK, SK>, T) -> BigInteger,
			                       decrypt: (Cryptaception<PK, SK>, BigInteger) -> T) {
		val keyGenBegin = System.currentTimeMillis()
		val crypta = keyGen(512)
		val keyGenEnd = System.currentTimeMillis()
		val keyGenElapsed = keyGenEnd - keyGenBegin
		
		println("CryptaceptionTest.encryptDecryptString> public key = ${crypta.publicKey}")
		println("CryptaceptionTest.encryptDecryptString> secret key = ${crypta.secretKey}")
		
		println("Encrypting \"${typeToString(value)}\"...")
		
		val encryptBegin = System.currentTimeMillis()
		val encryptedMessage = encrypt(crypta, value)
		val encryptEnd = System.currentTimeMillis()
		val encryptElapsed = encryptEnd - encryptBegin
		println("CryptaceptionTest.encryptDecryptString> Encrypted message: $encryptedMessage")
		
		println("Decrypting...")
		
		val decryptBegin = System.currentTimeMillis()
		val decryptedMessage = decrypt(crypta, encryptedMessage)
		val decryptEnd = System.currentTimeMillis()
		val decryptElapsed = decryptEnd - decryptBegin
		println("Decrypted message: \"$decryptedMessage\"")
		assertEquals(value, decryptedMessage)
		
		println("Time elapsed:")
		println("\tKey gen: $keyGenElapsed ms")
		println("\tEncryption: $encryptElapsed ms")
		println("\tDecryption: $decryptElapsed ms")
	}
}