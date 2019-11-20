package fr.polytech.berger.cryptaception

import java.math.BigInteger
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.util.*

abstract class Cryptaception<PK, SK>(
	private var _publicKey: PK,
	private var _secretKey: SK
): Observable(), ICrypt<PK, SK> {
	
	//region STATIC CONTEXT
	
	companion object {
		const val DEFAULT_KEY_SIZE_BITS = 512
	}
	
	//endregion
	
	//region PROPERTIES
	
	var publicKey: PK
		get() = _publicKey
		set(value) {
			_publicKey = value
			notifyObservers()
		}
	
	var secretKey: SK
		get() = _secretKey
		set(value) { _secretKey = value }
	
	//endregion
	
	//region METHODS
	
	
	
	//endregion
}
