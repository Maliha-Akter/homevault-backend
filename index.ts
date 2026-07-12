import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { MongoClient, ServerApiVersion, ObjectId, Collection, Db } from 'mongodb';
import { createRemoteJWKSet, jwtVerify, JWTPayload } from 'jose-cjs';

dotenv.config();

const uri = process.env.MONGODB_URI;
const port = process.env.MONGODB_PORT || 5000;

if (!uri) {
    console.error("Critical Error: MONGODB_URI environment variable is missing.");
    process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

// --- Document Interfaces & Types ---
interface CustomJWTPayload extends JWTPayload {
    id: string;
}

export interface AuthenticatedRequest extends Request {
    user?: CustomJWTPayload;
}

// --- MongoDB Client Setup ---
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// --- Remote JWKS Authentication Validation ---
const JWKS = createRemoteJWKSet(new URL(`${process.env.CLIENT_URL}/api/auth/jwks`));

const verifyToken = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: "Unauthorized: Missing Token" });
    }
    const token = authHeader.split(" ")[1];

    try {
        const { payload } = await jwtVerify(token, JWKS);
        req.user = payload as CustomJWTPayload;
        next();
    } catch (error: any) {
        console.error("JWT Verification Error:", error.message);
        return res.status(403).json({ message: "Forbidden: Invalid Token" });
    }
};

// --- Main Application Execution Lifecycle ---
async function run() {
    try {
        // 1. Establish database connection link
        await client.connect();
        
        const db: Db = client.db("homevault");
        // You can declare your collections here now:
        // const itemsCollection = db.collection("items");

        console.log("Database initialized. HomeVault collections ready.");

        // ==========================================
        //   PLACE ALL YOUR API ROUTES INSIDE HERE
        // ==========================================
        
        app.get('/', (req: Request, res: Response) => { 
            res.send('HomeVault API is active.');
        });

        app.listen(port, () => { 
            console.log(`Server running safely on port: ${port}`);
        });

    } catch (error) {
        console.error("Critical database assembly pipeline crash:", error);
    }
}
run().catch(console.dir);