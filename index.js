const crypto = require('crypto');

const algorithm = 'aes-256-ctr';

function encryptDecrypt( salt ) {
	try{
		
		salt = salt.toString()
		
	}catch ( e ) {
		
		throw new Error('encryptDecrypt: provide a string to salt the encryption');
		
	}
	const key = crypto
		.createHash('sha256')
		.update(String(salt))
		.digest();
	
	this.encrypt = function encrypt(value) {
		if (value == null) {
			throw new Error('provide a value to encrypt');
		}
		
		const iv = crypto.randomBytes(16);
		const cipher = crypto.createCipheriv(algorithm, key, iv);
		const encrypted = cipher.update(String(value), 'utf8', 'hex') + cipher.final('hex');
		
		return iv.toString('hex') + encrypted;
	};
	
	this.decrypt = function decrypt(value) {
		
		try{
			
			value = value.toString()
			
		}catch ( e ) {
			
			throw new Error('provide a value to decrypt');
			
		}
		
		const stringValue = String(value);
		const iv = Buffer.from(stringValue.slice(0, 32), 'hex');
		const encrypted = stringValue.slice(32);
		let legacyValue = false;
		let decipher;
		
		try {
			decipher = crypto.createDecipheriv(algorithm, key, iv);
		} catch (exception) {
			if (exception.message === 'Invalid IV length') {
				legacyValue = true;
			} else {
				throw exception;
			}
		}
		
		if (!legacyValue) {
			return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
		}
		
		const undeprecate = stringValue.slice(0, 16);
		const legacyEncrypted = stringValue.slice(16);
		decipher = crypto.createDecipheriv(algorithm, key, undeprecate);
		return decipher.update(legacyEncrypted, 'hex', 'utf8') + decipher.final('utf8');
	};
}

module.exports = encryptDecrypt;
