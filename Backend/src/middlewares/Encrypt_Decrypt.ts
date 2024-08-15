import e, { Request, Response } from "express";
const crypto = require('crypto');


export function encryptFunction(dataToEncrypt: any, passphrase: any) {
    // Derive key from passphrase using PBKDF2
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
    
    // Generate a random IV
    const iv = crypto.randomBytes(16);
    
    // Create cipher with key and IV
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    let encrypted = cipher.update(dataToEncrypt.toString(), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Combine the IV, salt, and the encrypted data (prepend the salt and IV)
    const ivHex = iv.toString('hex');
    const saltHex = salt.toString('hex');
    return `${saltHex}:${ivHex}:${encrypted}`;
}


export function decryptFunction(dataToDecrypt: any, passphrase: any) {
    // Split the encrypted data to get salt, IV, and the actual encrypted data
    const [saltHex, ivHex, encryptedData] = dataToDecrypt.split(':');
    
    // Convert hex values back to buffers
    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    
    // Derive key from passphrase using PBKDF2
    const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
    
    // Create decipher with key and IV
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}