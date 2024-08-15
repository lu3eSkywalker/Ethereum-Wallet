/*
  Warnings:

  - You are about to drop the column `mnemonics` on the `User` table. All the data in the column will be lost.
  - Added the required column `mnemonic` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `password` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "mnemonics",
ADD COLUMN     "mnemonic" TEXT NOT NULL,
ADD COLUMN     "password" TEXT NOT NULL;
