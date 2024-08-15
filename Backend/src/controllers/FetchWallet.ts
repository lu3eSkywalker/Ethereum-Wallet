import e, { Request, Response } from "express";
import {z} from 'zod';
import dotenv, { parse } from 'dotenv';
dotenv.config();
const crypto = require('crypto');

import { PrismaClient } from '@prisma/client';
import { Wallet } from 'ethers';
import { generateMnemonic, mnemonicToSeedSync } from "bip39";
import { privateToPublic, bufferToHex } from 'ethereumjs-util';
import bcrypt from 'bcrypt';
import { decryptFunction, encryptFunction } from "../middlewares/Encrypt_Decrypt";
import authenticate from "../middlewares/Middleware";
const { hdkey } = require('ethereumjs-wallet');


const prisma = new PrismaClient();


export const fetchWallet = async(req: Request, res: Response): Promise<void> => {
    try {
        authenticate(req, res, async() => {
            const wallet_id: any = req.params.id;

            const walletId = parseInt(wallet_id);
    
            if(!walletId) {
                res.status(404).json({
                    success: false,
                    message: "No Data Found"
                })
                return;
            }
    
            const wallet = await prisma.wallet.findUnique({
                where: {
                    id: walletId
                }
            });
    
            res.status(200).json({
                success: true,
                data: wallet,
                message: "Data Fetched Successfully"
                });
            })
        }
        catch(error) {
            console.log('Error: ', error)
            res.status(500).json({
                success: false,
                message: 'Cannot Fetch the wallet'
            })
        }
}

export const fetchallWalletsofAUser = async(req: Request, res: Response): Promise<void> => {
    try {
        authenticate(req, res, async() => {
            const user_Id: any = req.params.id;

            const userId = parseInt(user_Id);
    
            if(!userId) {
                res.status(404).json({
                    success: false,
                    message: "Successfully liked the post"
                })
                return;
            }
    
            const wallets = await prisma.user.findUnique({
                where: {
                    id: userId
                },
                select: {
                    wallet: true
                }
            });
    
            res.status(200).json({
                success: true,
                data: wallets,
                message: "Successfully fetched the wallets"
            })
        })
    }
    catch(error) {
        console.log('Error: ', error)
        res.status(500).json({
            success: false,
            message: 'Cannot Fetch the wallet'
        })
    }
}


export const createNewWallet = async(req: Request, res: Response): Promise<void> => {
    try {
        authenticate(req, res, async() => {
            const {userId, passphrase} = req.body

            if(!userId) {
                res.status(404).json({
                    success: false,
                    message: "No Data Found"
                })
                return;
            }
    
            const wallets = await prisma.user.findUnique({
                where: {
                    id: userId
                },
                select: {
                    wallet: true,
                    encryptedMnemonic: true,
                    password: true
                }
            });
    
            const password = wallets?.password ?? '';
    
            const compare = await bcrypt.compare(passphrase, password);
    
            if(compare) {
                
                const count: number = wallets?.wallet.length ?? 0;
    
                const encryptedMnemonic = wallets?.encryptedMnemonic ?? '';
    
                const mnemonic = decryptFunction(encryptedMnemonic, passphrase)
    
                const seed = mnemonicToSeedSync(mnemonic);
        
                const hdwallet = hdkey.fromMasterSeed(seed);
        
                const path = `m/44'/60'/${count}/0/0`;
                const hierarchichalWallet = hdwallet.derivePath(path).getWallet();
        
                const private_key = hierarchichalWallet.getPrivateKey();
                const publicKey_Buffer = privateToPublic(private_key);
                const public_key = bufferToHex(publicKey_Buffer);
        
                const ethereumWallet = new Wallet(private_key);

                const privateKey = private_key.toString("hex");
    
                const encryptedPrivateKey = encryptFunction(privateKey, password);
    
                const walletAdd = await prisma.wallet.create({
                    data: {
                        userId: userId,
                        encryptedPrivateKey: encryptedPrivateKey,
                        publicKey: public_key,
                        ethereumAddress: ethereumWallet.address
                    }
                })
        
                res.status(200).json({
                    success: true,
                    data: walletAdd,
                    message: 'Successfully made a new Wallet'
                })
    
            } else {
                res.status(401).json({
                    success: false,
                    message: 'Passphrase is wrong'
                })
            }
        })
    }
    catch(error) {
        console.log('Error: ', error)
        res.status(500).json({
            success: false,
            message: 'Cannot make the new wallet'
        })
    }
}


  export const decryptedPrivateKey = async(req: Request, res: Response): Promise<void> => {
    try {
        const {passphrase, userId, walletId} = req.body;

        const userPassword = await prisma.user.findUnique({
            where: {
                id: userId
            },
            select: {
                password: true
            }
        });

        const wallet = await prisma.wallet.findUnique({
            where: {
                id: walletId
            },
            select: {
                encryptedPrivateKey: true
            }
        })

        const hashedPassword = userPassword?.password ?? '';
        const encryptedprivateKey = wallet?.encryptedPrivateKey ?? '';

        const compare = await bcrypt.compare(passphrase, hashedPassword);

        if(compare) {
            const decryptedPrivateKey = decryptFunction(encryptedprivateKey, passphrase);
            console.log(decryptedPrivateKey);

            res.status(200).json({
                success: true,
                data: decryptedPrivateKey,
                message: 'Successfully decrypted the private key'
            });

        } else {
            res.status(401).json({
                success: false,
                message: 'Passphrase incorrect'
            });
        }
    }
    catch(error) {
        console.log('Error: ', error);
        res.status(500).json({
            success: false,
            message: 'Cannot fetch the private key'
        });
    }
};
