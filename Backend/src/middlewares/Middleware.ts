import { NextFunction, Request, Response } from "express";

import jwt, { Secret } from 'jsonwebtoken';

declare global {
    namespace Express {
        interface Request {
            user?: any;
        }
    }
}

const authenticate = (req: Request, res: Response, next: NextFunction) => {
    const token = req.header('Authorization');

    if(!token) {
        return res.status(401).json({ message: 'Unauthorized: Missing token' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET as Secret);
        req.user = decoded;
        next();
    }
    catch(error) {
        return res.status(401).json({ message: 'Unauthorized: Invalid token'})
    }
}

export default authenticate;