-- CreateTable
CREATE TABLE "Blacklistedtoken" (
    "id" SERIAL NOT NULL,
    "token" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Blacklistedtoken_pkey" PRIMARY KEY ("id")
);
