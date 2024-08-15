/*
  Warnings:

  - Added the required column `ethereumAddress` to the `Wallet` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Wallet" ADD COLUMN     "ethereumAddress" TEXT NOT NULL,
ALTER COLUMN "privateKey" SET DATA TYPE TEXT,
ALTER COLUMN "publicKey" SET DATA TYPE TEXT;
