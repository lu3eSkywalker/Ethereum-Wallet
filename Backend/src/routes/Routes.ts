import express from 'express';
import { signupUser } from '../controllers/Login_Signup';
import { createNewWallet, decryptedPrivateKey, fetchallWalletsofAUser, fetchWallet } from '../controllers/FetchWallet';

const router: express.Router = express.Router();

const app = express();

router.post('/signup', signupUser);
router.post('/addwallet', createNewWallet);

router.post('/decryptedprivatekey', decryptedPrivateKey)


router.get('/getwallet/:id', fetchWallet);
router.get('/fetchallwalletsofuser/:id', fetchallWalletsofAUser);

export default router;