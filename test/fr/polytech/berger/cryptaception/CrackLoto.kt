package fr.polytech.berger.cryptaception

import com.sun.org.apache.xpath.internal.operations.Bool
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.collections.ArrayList
import kotlin.collections.HashMap

internal class CrackLoto {
	
	lateinit var rsa: RSA
	lateinit var lotoNumber: ArrayList<Number>
	
	@BeforeEach
	fun setup() {
		lotoNumber = arrayListOf(1, 28, 49, 34, 14, 15)
		rsa = RSA.randomCryptaception()
	}
	
	@Test
	fun crackLotoEncryptionSeparated() {
		// Encryption
		val encryptedMessage = ArrayList<Number>(lotoNumber.size)
		for (loto in lotoNumber)
			encryptedMessage.add(rsa.encrypt(loto))
		
		// Attempt to decrypt
		val encryptionMap = HashMap<Int, BigInteger>()
		for (i in 1..49)
			encryptionMap[i] = rsa.encrypt(i)
		val decryptedMessage = ArrayList<Int>(lotoNumber.size)
		for (m in encryptedMessage) {
			for (loto in encryptionMap.keys) {
				if (m == encryptionMap[loto]) {
					decryptedMessage.add(loto)
					break
				}
			}
		}
		println("Decrypted loto numbers: $decryptedMessage")
		assertEquals(lotoNumber, decryptedMessage)
	}
	
	fun isAscending(list: List<Int>): Boolean {
		var lastElement: Int = Int.MIN_VALUE
		for (x in list) {
			if (x > lastElement) return false
			lastElement = x
		}
		return true
	}
	
	fun max(vararg list: Int): Int {
		var m = Int.MIN_VALUE
		for (x in list)
			if (m > x)
				m = x
		return m
	}
	
	@Test
	@Disabled
	fun crackLotoNumberAscending() {
		// Encryption
		lotoNumber.sortBy { x -> x.toInt() }
		val encryptedMessage = rsa.encrypt(lotoNumber.joinToString { x -> x.toString() })
		
		// Attempt to decrypt
		var encryption = BigInteger.ZERO
		var numbers = ArrayList<Number>()
		var decryptedMessage: ArrayList<Number>? = null
		val beginTime = System.currentTimeMillis()
		var endTime = 0L
		for (a in 1..49) {
			for (b in a..49) {
//				if (!(a <= b))
//					continue
				for (c in max(a, b)..49) {
//					if (!(a <= b && b <= c))
//						continue
					for (d in max(a, b, c)..49) {
//						if (!(a <= b && b <= c && c <= d))
//							continue
						for (e in max(a, b, c, d)..49) {
//							if (!(a <= b && b <= c && c <= d && d <= e))
//								continue
							for (f in max(a, b, c, d, e)..49) {
//								if (!(a <= b && b <= c && c <= d && d <= e && e <= f))
//									continue
								numbers = arrayListOf(a, b, c, d, e, f)
								encryption = rsa.encrypt(numbers.joinToString { x -> x.toString() })
								if (encryption == encryptedMessage) {
									decryptedMessage = numbers
									break
								}
							}
						}
					}
				}
			}
		}
		endTime = System.currentTimeMillis()
		if (!decryptedMessage.isNullOrEmpty())
			println("DECRYPTED! The loto numbers are: $numbers")
		else
			println("Could not decrypt loto numbers :(")
		println("It took ${(endTime - beginTime)/1000} s = ${(endTime - beginTime)/(1000 * 60)} minutes.")
	}
}