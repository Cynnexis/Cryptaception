package fr.polytech.berger.cryptaception

import java.math.BigInteger
import java.util.*
import com.sun.istack.internal.NotNull
import kotlin.math.abs


object PrimeManager {
	
	const val FERMAT_MAX_TRIAL = 2
	
	fun fermatTest(@NotNull n: BigInteger): Boolean {
		if (n == BigInteger.ONE)
			return false
		
		if (n == BigInteger("2"))
			return true
		
		if (n == BigInteger("3"))
			return true
		
		val random = Random(System.currentTimeMillis())
		
		for (i in 0 until FERMAT_MAX_TRIAL) {
			var a = BigInteger.ZERO
			
			while (a == n || a == BigInteger.ZERO || a == BigInteger.ONE)
				a = BigInteger(abs(random.nextInt(Integer.MAX_VALUE)).toString())
			
			if (a.gcd(n) > BigInteger.ONE)
				return false
			
			val result = a.modPow(n.subtract(BigInteger.ONE), n)
			
			if (result != BigInteger.ONE)
				return false
		}
		
		return true
	}
	fun fermatTest(n: Int): Boolean {
		return fermatTest(BigInteger(n.toString()))
	}
	
	fun generateRandomPrimeNumber(bits: Int): BigInteger {
		val random = Random(System.currentTimeMillis())
		var number = BigInteger.probablePrime(bits, random)
		
		while (!fermatTest(number))
			number = BigInteger.probablePrime(bits, random)
		
		return number
	}
}