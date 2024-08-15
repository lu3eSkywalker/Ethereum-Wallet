/*
  Warnings:

  - You are about to drop the column `mnemonic` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "mnemonic",
ADD COLUMN     "encryptedMnemonic" TEXT;
