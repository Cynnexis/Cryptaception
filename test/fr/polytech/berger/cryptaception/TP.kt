package fr.polytech.berger.cryptaception

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.shadow.com.univocity.parsers.conversions.BigIntegerConversion
import java.math.BigInteger
import java.util.*
import kotlin.collections.ArrayList
import kotlin.collections.HashMap


internal class TP {

    @AfterEach
    fun afterEach() {
        println()
    }

    @Test
    fun TP1() {
        val random = Random(System.currentTimeMillis())

        println("Exercise 6")

        val p = PrimeManager.generateRandomPrimeNumber(512)
        val q = PrimeManager.generateRandomPrimeNumber(512)

        println("p = $p")
        println("q = $q")

        println()
        println("Exercise 7")

        val n = p.multiply(q)
        val phi_n = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE))

        println("n = $n")
        println("Φ_n = $phi_n")

        println()
        println("Exercise 8")

        var e = BigInteger.ZERO

        while (e.gcd(phi_n) != BigInteger.ONE)
            e = PrimeManager.generateRandomPrimeNumber(16)

        println("e = $e")

        println()
        println("Exercise 9")

        val d = e.modInverse(phi_n)

        println("d = $d")

        println("e * d mod Φ_n = 1")
        assertEquals(BigInteger.ONE, e.multiply(d).mod(phi_n))

        println()
        println("Exercise n°10")

        var x = BigInteger.ZERO
        while (x == BigInteger.ZERO)
            x = BigInteger(random.nextInt(16), random)

        val X = x.modPow(e, n)

        println("x = $x")
        println("X = $X")

        val result = X.modPow(d, n)

        println("X^d mod n = $result")

        val publicKey = Pair<BigInteger, BigInteger>(n, e)
        val secretKey = d

        println("public key = $publicKey")
        println("secret key = $secretKey")

        /*
		clef public = (n, e)
		clef privée = d

		x^e => encrypter
		x^d => décrypter
		 */
    }
    
    @Test
    fun crackLoto() {
        // Voyante
        val lotoNumber = arrayListOf(1, 28, 49, 34, 14, 15)
        val crypta = Cryptaception.randomCryptaception()
        val publicKey = crypta.publicKey
    
        val encryptedMessage = ArrayList<Number>(lotoNumber.size)
        for (loto in lotoNumber)
            encryptedMessage.add(crypta.encrypt(loto))
    
        // Attaquant
        val encryptionMap = HashMap<Int, BigInteger>()
        for (i in 1..49)
            encryptionMap[i] = crypta.encrypt(i)
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
}