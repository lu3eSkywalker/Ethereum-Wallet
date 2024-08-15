import { Request, Response } from "express";
import {z} from 'zod';
import bcrypt from 'bcrypt';
import dotenv, { parse } from 'dotenv';
dotenv.config();
const crypto = require('crypto');
import jwt, { Secret } from 'jsonwebtoken';


import { PrismaClient } from '@prisma/client';
import { generateMnemonic, mnemonicToSeedSync } from "bip39";
import { privateToPublic, bufferToHex } from 'ethereumjs-util';
import { Wallet } from "ethers";
import { encryptFunction } from "../middlewares/Encrypt_Decrypt";

const { hdkey } = require('ethereumjs-wallet');
const secretjwt: string = process.env.JWT_SECRET || '';


const prisma = new PrismaClient();

const SignUserSchema = z.object({
    username: z.string().min(2).max(20),
    email: z.string().email(),
    password: z.string().min(5)
})

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


            const encrypted_PrivateKey = encryptFunction(privateKey, password);

            const encryptedMnemonic = encryptFunction(mnemonic, password);


            const response = await prisma.user.create({
                data: {
                    username,
                    email, 
                    password: hashedPassword,
                    encryptedMnemonic: encryptedMnemonic
                }
            });

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
                anotherData: anotherResponse,
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

const UserLoginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(5)
})

export const loginUser = async(req: Request<{ email: string, password: string}>, res: Response): Promise<void> => {
    try {
        const parsedInput = UserLoginSchema.safeParse(req.body);
        if(!parsedInput.success) {
            res.status(411).json({
                error: parsedInput.error
            })
            return;
        }

        const email = parsedInput.data.email;
        const password = parsedInput.data.password;

        const user = await prisma.user.findUnique({
            where: {
                email: email,
            }
        });

        if(!user) {
            res.status(404).json({
                success: false,
                message: 'User not registered',
            });
            return
        }

        const payload = {
            email: user.email,
            name: user.username,
            id: user.id
        }

        const compare = await bcrypt.compare(password, user.password);

        if(compare) {
            const token = jwt.sign({payload}, secretjwt, { expiresIn: "24hr"} )

            res.status(200).json({
                success: true,
                data: user,
                token: token,
                message: 'Logged in successfully'
            });
        } else {
            res.status(401).json({
                success: false,
                message: "Password Incorrect"
            });
        }
    }
    catch(error) {
        console.log('Error: ', error)
        res.status(500).json({
            success: false,
            message: 'Cannot Login In',
        })
    }
}

export const logout = async(req: Request, res: Response): Promise<void> => {
    try {
        const token = req.headers.authorization?.split(' ')[1] ?? '';

        await prisma.blacklistedtoken.create({
            data: {
                token: token,
                createdAt: new Date()
            }
        });

        res.status(200).json({
            success: true,
            message: 'User Logged out successfully'
        })

    }
    catch(error) {
        console.log("Error: ", error);
        res.status(500).json({
            success: false,
            message: "Internal server Error"
        })
    }
}