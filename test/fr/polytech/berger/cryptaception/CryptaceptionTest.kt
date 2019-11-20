package fr.polytech.berger.cryptaception

import org.junit.jupiter.api.BeforeEach

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.math.BigInteger

internal class CryptaceptionTest {

	private lateinit var crypta: Cryptaception
	
	@BeforeEach
	fun setUp() {
		crypta = Cryptaception.randomCryptaception(512)
	}
	
	@Test
	fun encryptDecryptString() {
		encryptDecrypt<String>(
			"Hello world",
			{ x -> x },
			{ crypta, message -> crypta.encrypt(message) },
			{ crypta, encryptedMessage -> crypta.decryptToString(encryptedMessage) }
		)
	}
	
	@Test
	fun encryptDecryptInt() {
		encryptDecrypt<Int>(
			42,
			{ x -> x.toString() },
			{ crypta, message -> crypta.encrypt(message) },
			{ crypta, encryptedMessage -> crypta.decryptToInt(encryptedMessage) }
		)
	}
	
	private fun <T> encryptDecrypt(value: T,
			                       typeToString: (T) -> String,
			                       encrypt: (Cryptaception, T) -> BigInteger,
			                       decrypt: (Cryptaception, BigInteger) -> T) {
		val keyGenBegin = System.currentTimeMillis()
		crypta = Cryptaception.randomCryptaception(512)
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