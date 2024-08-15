import { Request, Response } from "express";
import {z} from 'zod';
import bcrypt from 'bcrypt';
import dotenv, { parse } from 'dotenv';
dotenv.config();
// import { crypto } from 'crypto';
const crypto = require('crypto');

import { PrismaClient } from '@prisma/client';
import { generateMnemonic, mnemonicToSeedSync } from "bip39";
import { privateToPublic, bufferToHex } from 'ethereumjs-util';
import { Wallet } from "ethers";

const { hdkey } = require('ethereumjs-wallet');

const prisma = new PrismaClient();

const SignUserSchema = z.object({
    username: z.string().min(2).max(20),
    email: z.string().email(),
    password: z.string().min(5)
})

function encryptPrivateKey(privateKey: any, passphrase: any) {
    // Derive key from passphrase using PBKDF2
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
    
    // Generate a random IV
    const iv = crypto.randomBytes(16);
    
    // Create cipher with key and IV
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    let encrypted = cipher.update(privateKey.toString(), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Combine the IV, salt, and the encrypted data (prepend the salt and IV)
    const ivHex = iv.toString('hex');
    const saltHex = salt.toString('hex');
    return `${saltHex}:${ivHex}:${encrypted}`;
}


export const signupUser = async(req: Request, res: Response): Promise<void> => {
    try {
        const parsedInput = SignUserSchema.safeParse(req.body);
        if(!parsedInput.success) {
            res.status(411).json({
                error: parsedInput.error
            })
            return;
        }

        const username = parsedInput.data.username;
        const email = parsedInput.data.email;
        const password = parsedInput.data.password;

        let hashedPassword: string;
            hashedPassword = await bcrypt.hash(password, 10);

            const mnemonic = generateMnemonic();

            const response = await prisma.user.create({
                data: {
                    username,
                    email, 
                    password: hashedPassword,
                    mnemonic
                }
            });

            const seed = mnemonicToSeedSync(mnemonic);
            const hdwallet = hdkey.fromMasterSeed(seed);
            const derivationPath = "m/44'/60'/0'/0/0";
            const childWallet = hdwallet.derivePath(derivationPath).getWallet();

            // Get the private key
            const private_Key = childWallet.getPrivateKey();

            // Compute the public key using ethereumjs-util
            const publicKeyBuffer = privateToPublic(private_Key);
            const publicKey = bufferToHex(publicKeyBuffer);

            const wallet = new Wallet(private_Key);
            const ethereumAddress = wallet.address;

            const privateKey = private_Key.toString('hex');


            const encrypted_PrivateKey = encryptPrivateKey(privateKey, password);

            const anotherResponse = await prisma.wallet.create({
                data: {
                    userId: response.id,
                    encryptedPrivateKey: encrypted_PrivateKey,
                    publicKey,
                    ethereumAddress
                }
            })

            res.status(200).json({
                success: true,
                data: response,
                message: 'Signed up Successfully'
            })
    }
    catch(error) {
        console.log('Error: ', error)
        res.status(500).json({
            success: false,
            message: 'Entry Creation Failed',
        })
    }
}