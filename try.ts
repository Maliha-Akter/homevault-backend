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

app.use(cors({
  origin: "http://localhost:3000",
  allowedHeaders: ["Content-Type", "Authorization", "Accept"]
}));
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
    // 🔍 1. Log incoming tracking info
    console.log("=== INCOMING AUTHENTICATION CHECK ===");
    console.log("Request Path:", req.path);
    console.log("All Headers received:", req.headers);
    console.log("Cookies received (if cookie-parser is used):", (req as any).cookies);
    console.log("Authorization Header:", req.headers.authorization);

    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn("❌ Auth validation failed: Authorization header is missing or does not start with 'Bearer '");
        return res.status(401).json({ message: "Unauthorized: Missing Token" });
    }

    const token = authHeader.split(" ")[1];
    console.log("Extracted Token substring:", token.substring(0, 15) + "...");

    try {
        const { payload } = await jwtVerify(token, JWKS);
        req.user = payload as CustomJWTPayload;
        console.log("✅ Token successfully verified! User ID:", req.user.id);
        next();
    } catch (error: any) {
        console.error("❌ JWT Verification Error:", error.message);
        return res.status(403).json({ message: "Forbidden: Invalid Token" });
    }
};

// --- Main Application Execution Lifecycle ---
async function run() {
    try {
        // 1. Establish database connection link
        await client.connect();

        const db: Db = client.db("homevault");
        // 1. category table
        interface CategoryDocument {
            name: string;
            icon: string;
            image: string;
            description: string;
            createdBy: string;
            isDefault: boolean;
            isApproved: boolean;
            createdAt: Date;
        }

        const categoriesCollection: Collection<CategoryDocument> = db.collection('categories');

        // 2. Updated POST API Endpoint
        app.post('/api/categories', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const { name, icon, image, description } = req.body;
                const userId = req.user?.id || "unknown";

                // Basic validation
                if (!name) {
                    return res.status(400).json({
                        success: false,
                        message: "Category name parameter is mandatory."
                    });
                }

                // Prevent duplicate names safely by checking case-insensitively using regex matching
                const existing = await categoriesCollection.findOne({
                    name: { $regex: `^${name.trim()}$`, $options: 'i' }
                });

                if (existing) {
                    return res.status(409).json({
                        success: false,
                        message: "A category with this name already exists."
                    });
                }

                const newCategory: CategoryDocument = {
                    name: name.trim(),
                    icon: icon || "Box",
                    image: image || "",
                    description: description || "",
                    createdBy: userId,
                    isDefault: false,
                    isApproved: false,
                    createdAt: new Date()
                };

                const result = await categoriesCollection.insertOne(newCategory);

                return res.status(201).json({
                    success: true,
                    message: "Category added successfully and is pending approval.",
                    insertedId: result.insertedId
                });

            } catch (error: any) {
                console.error("Error creating category:", error);
                return res.status(500).json({ success: false, message: "Internal server error." });
            }
        });
        // 3. GET API Endpoint (with text search and radio-type type filtering)
        // 3. GET API Endpoint (Filtering dynamically by Category Name)
        app.get('/api/categories', async (req: Request, res: Response) => {
            try {
                const { search, categoryName } = req.query;
                const query: any = {};

                // 1. Text Search Filter (for the search input box)
                if (search) {
                    query.name = { $regex: search.toString().trim(), $options: 'i' };
                }

                // 2. Exact Category Name Filter (for the radio pills selection)
                if (categoryName && categoryName.toString().toLowerCase() !== 'all') {
                    query.name = categoryName.toString().trim();
                }

                // Fetch categories sorted by newest creation date
                const categories = await categoriesCollection
                    .find(query)
                    .sort({ createdAt: -1 })
                    .toArray();

                return res.status(200).json({
                    success: true,
                    count: categories.length,
                    data: categories
                });

            } catch (error: any) {
                console.error("Error fetching categories:", error);
                return res.status(500).json({
                    success: false,
                    message: "Internal server error."
                });
            }
        });

        interface InventoryDocument {
            userId: string;
            itemName: string;
            description: string;
            categoryId: string;
            categoryName: string;
            image: string; // Simplified single image field
            brand: string;
            purchaseDate: Date;
            purchasePrice: number;
            condition: "New" | "Excellent" | "Good" | "Fair" | "Poor";
            status: "Active" | "Sold" | "Lost" | "Damaged" | "Donated";
            createdAt: Date;
            updatedAt: Date;
        }

        const inventoryCollection: Collection<InventoryDocument> = db.collection('inventory');

        // 2. POST API Endpoint: Create Inventory Item
        app.post('/api/inventory', verifyToken, async (req: any, res: Response) => {
            try {
                const {
                    title,
                    categoryId,
                    brand,
                    room,
                    purchaseDate,
                    purchasePrice,
                    estimatedValue,
                    warrantyExpiry,
                    condition,
                    image,
                    notes
                } = req.body;

                const userId = req.user?.id || "unknown";

                // Validate strictly matching properties marked as required by schema or form layout
                if (!title || !categoryId || !brand || !room || !purchaseDate || !purchasePrice || !estimatedValue || !condition) {
                    return res.status(400).json({
                        success: false,
                        message: "Missing mandatory inventory tracking parameters based on structural system rules."
                    });
                }

                // Structuring the data payload exactly to your target schema layout
                const newInventoryItem = {
                    userId,
                    categoryId,
                    title: title.trim(),
                    brand: brand.trim(),
                    room: room.trim(),
                    purchaseDate: new Date(purchaseDate),
                    purchasePrice: Number(purchasePrice),
                    estimatedValue: Number(estimatedValue),
                    warrantyExpiry: warrantyExpiry ? new Date(warrantyExpiry) : null,
                    condition,
                    image: image || "",
                    notes: notes || "",
                    createdAt: new Date()
                };

                const result = await inventoryCollection.insertOne(newInventoryItem);

                return res.status(201).json({
                    success: true,
                    message: "Asset logged into HomeVault registry successfully.",
                    insertedId: result.insertedId
                });

            } catch (error) {
                console.error("Error adding to inventory:", error);
                return res.status(500).json({ success: false, message: "Internal server error." });
            }
        });
        // 3. GET API Endpoint: Retrieve Inventory Items (with User Filter)
        app.get('/api/inventory', verifyToken, async (req: any, res: Response) => {
            try {
                const userId = req.user?.id;
                const { categoryId } = req.query;

                if (!userId) {
                    return res.status(401).json({ success: false, message: "Unauthorized." });
                }

                const query: any = { userId: userId };

                if (categoryId) {
                    query.categoryId = categoryId.toString();
                }

                const items = await inventoryCollection
                    .find(query)
                    .sort({ createdAt: -1 })
                    .toArray();

                return res.status(200).json({
                    success: true,
                    count: items.length,
                    data: items
                });

            } catch (error) {
                console.error("Error fetching inventory items:", error);
                return res.status(500).json({ success: false, message: "Internal server error." });
            }
        });

        // 2. UPDATE INVENTORY ITEM (Syncing explicit structure schema mapping options)
        app.put('/api/inventory/:id', verifyToken, async (req: any, res: Response) => {
            try {
                const itemId = req.params.id;
                const userId = req.user?.id;

                if (!userId) {
                    return res.status(401).json({ success: false, message: "Unauthorized." });
                }

                const {
                    categoryId,
                    title,
                    brand,
                    room,
                    purchaseDate,
                    purchasePrice,
                    estimatedValue,
                    warrantyExpiry,
                    condition,
                    image,
                    notes
                } = req.body;

                const existingItem = await inventoryCollection.findOne({
                    _id: new ObjectId(itemId),
                    userId: userId
                });

                if (!existingItem) {
                    return res.status(404).json({
                        success: false,
                        message: "Asset not found or you do not have permission to modify it."
                    });
                }

                const updatedData = {
                    $set: {
                        categoryId: categoryId?.trim(),
                        title: title?.trim(),
                        brand: brand?.trim(),
                        room: room?.trim(),
                        purchaseDate: purchaseDate ? new Date(purchaseDate) : null,
                        purchasePrice: Number(purchasePrice),
                        estimatedValue: Number(estimatedValue),
                        warrantyExpiry: warrantyExpiry ? new Date(warrantyExpiry) : null,
                        condition: condition?.trim(),
                        image: image?.trim(),
                        notes: notes?.trim(),
                        updatedAt: new Date()
                    }
                };

                await inventoryCollection.updateOne({ _id: new ObjectId(itemId) }, updatedData);

                return res.status(200).json({
                    success: true,
                    message: "Asset updated successfully in your Vault."
                });

            } catch (error) {
                console.error("Error updating inventory asset:", error);
                return res.status(500).json({ success: false, message: "Internal server error." });
            }
        });

        // 3. DELETE INVENTORY ITEM
        app.delete('/api/inventory/:id', verifyToken, async (req: any, res: Response) => {
            try {
                const itemId = req.params.id;
                const userId = req.user?.id;

                if (!userId) {
                    return res.status(401).json({ success: false, message: "Unauthorized." });
                }

                const result = await inventoryCollection.deleteOne({
                    _id: new ObjectId(itemId),
                    userId: userId
                });

                if (result.deletedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Asset could not be found or you lack structural ownership permissions."
                    });
                }

                return res.status(200).json({
                    success: true,
                    message: "Asset deleted from your Vault successfully."
                });

            } catch (error) {
                console.error("Error destroying inventory document:", error);
                return res.status(500).json({ success: false, message: "Internal server error." });
            }
        });
        app.get('/api/user/profile', verifyToken, async (req: any, res: Response) => {
            try {
                const userId = req.user?.id;

                if (!userId) {
                    return res.status(401).json({ success: false, message: "Unauthorized profile context access." });
                }

                // Handle both standard string IDs and raw ObjectIds gracefully based on your schema initialization setup
                const queryId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;

                // Better-Auth collection defaults to "user" table structure
                const user = await db.collection("user").findOne(
                    { _id: queryId },
                    { projection: { password: 0 } } // Extra layer protection safeguard
                );

                if (!user) {
                    return res.status(404).json({ success: false, message: "User profile registry not found." });
                }

                return res.status(200).json({
                    success: true,
                    user: {
                        ...user,
                        _id: user._id.toString() // Standardize the ID formatting for frontend consistency
                    }
                });

            } catch (error) {
                console.error("Backend Profile Fetch Error:", error);
                return res.status(500).json({ success: false, message: "Internal server registry error." });
            }
        });

        // PUT: Modify specific user attributes securely 
        app.put('/api/user/profile', verifyToken, async (req: any, res: Response) => {
            try {
                const userId = req.user?.id;
                const { name, image } = req.body;

                if (!userId) {
                    return res.status(401).json({ success: false, message: "Unauthorized profile state adjustment." });
                }

                if (!name || !image) {
                    return res.status(400).json({ success: false, message: "Missing mandatory fields." });
                }

                const queryId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;

                const updateResult = await db.collection("user").updateOne(
                    { _id: queryId },
                    {
                        $set: {
                            name: name.trim(),
                            image: image.trim(),
                            updatedAt: new Date()
                        }
                    }
                );

                if (updateResult.matchedCount === 0) {
                    return res.status(404).json({ success: false, message: "Profile update destination target missing." });
                }

                return res.status(200).json({
                    success: true,
                    message: "Profile settings modified successfully."
                });

            } catch (error) {
                console.error("Backend Profile Update Error:", error);
                return res.status(500).json({ success: false, message: "Internal server handling error." });
            }
        });
        const verifyAdmin = (req: any, res: Response, next: any) => {
            if (!req.user || req.user.role !== "admin") {
                return res.status(403).json({
                    success: false,
                    message: "Access Denied. Elevated Administrative authorization level required."
                });
            }
            next();
        };

        // GET: Fetch all application user parameters inside the Better-Auth "user" collection matrix
        app.get('/api/admin/users', verifyToken, verifyAdmin, async (req: any, res: Response) => {
            // 1. Log entry check
            console.log(">>> [GET /api/admin/users] Route handler successfully reached.");
            console.log(">>> [GET /api/admin/users] Decoded user from middleware token:", req.user);

            try {
                // Querying structural data targets cleanly while dropping sensitive credentials
                const usersFromDb = await db.collection("user")
                    .find({})
                    .project({ password: 0, salt: 0 })
                    .sort({ createdAt: -1 })
                    .toArray();

                // 2. Log database count
                console.log(`>>> [GET /api/admin/users] Found ${usersFromDb.length} users in database.`);

                // Map data safely to match frontend expectations with validation check guards
                const formattedUsers = usersFromDb.map(user => {
                    const parsedId = user._id ? user._id.toString() : "";
                    return {
                        id: parsedId,
                        name: user.name || "Anonymous User",
                        email: user.email || "",
                        image: user.image || "",
                        role: user.role || "user",
                        isBlocked: !!user.isBlocked,
                        createdAt: user.createdAt ? new Date(user.createdAt).toISOString() : new Date().toISOString()
                    };
                });

                return res.status(200).json({
                    success: true,
                    users: formattedUsers
                });

            } catch (error) {
                console.error("❌ [GET /api/admin/users] Error fetching administrative registry data:", error);
                return res.status(500).json({ success: false, message: "Internal directory mapping error." });
            }
        });

        // PATCH: Toggle absolute state mutation metrics (Block / Active Status)
        app.patch('/api/admin/users/toggle-block', verifyToken, verifyAdmin, async (req: any, res: Response) => {
            // 1. Log entry check
            console.log(">>> [PATCH /api/admin/users/toggle-block] Body received:", req.body);

            try {
                const { userId, isBlocked } = req.body;

                if (!userId) {
                    console.log("⚠️ [PATCH /api/admin/users/toggle-block] Rejected: Missing userId");
                    return res.status(400).json({ success: false, message: "Target identity key signature missing." });
                }

                // Handle both standard string IDs and raw ObjectIds gracefully based on database layout
                const targetId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;

                // Perform atomic update inside user table
                const updateResult = await db.collection("user").updateOne(
                    { _id: targetId },
                    {
                        $set: {
                            isBlocked: Boolean(isBlocked),
                            updatedAt: new Date()
                        }
                    }
                );

                console.log(">>> [PATCH /api/admin/users/toggle-block] DB Update Result:", updateResult);

                if (updateResult.matchedCount === 0) {
                    console.log(`⚠️ [PATCH /api/admin/users/toggle-block] User not found for ID: ${userId}`);
                    return res.status(404).json({ success: false, message: "Identity document context not found." });
                }

                const systemMessage = isBlocked
                    ? "Account credential access has been suspended successfully."
                    : "Account access authorization has been fully restored.";

                return res.status(200).json({
                    success: true,
                    message: systemMessage
                });

            } catch (error) {
                console.error("❌ [PATCH /api/admin/users/toggle-block] Error executing status profile toggle modification:", error);
                return res.status(500).json({ success: false, message: "Internal server execution fault." });
            }
        });
        console.log("Database initialized. HomeVault collections ready.");

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