import express from 'express';
import { PrismaClient } from '@prisma/client';
import cors from 'cors';
import ethereumWalletAPIroutes from './routes/Routes';
import { createServer } from 'http';





const app = express();
const PORT = process.env.PORT || 4000;
const prisma = new PrismaClient();

app.use(express.json());
app.use('/api/v1', ethereumWalletAPIroutes);
const server = createServer(app);

const dbConnect = async () => { 
    try {
        await prisma.$connect();
        console.log('Connected to the database');
    } catch(error) {
        console.log('Database connection error: ', error);
        process.exit(1);
    }
};

dbConnect();

server.listen(PORT, () => {
    console.log(`Server started successfully at ${PORT}`);
});

process.on('beforeExit', async () => {
    await prisma.$disconnect();
    console.log('Disconnected from database');
});

process.on('SIGINT', async () => {
    await prisma.$disconnect();
    console.log('Disconnected from database');
    process.exit(0);
});