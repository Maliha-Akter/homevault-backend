import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser'; // 1. Imported
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

app.use(express.json());
app.use(cookieParser()); // 1. Added middleware

app.use(cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
    exposedHeaders: ["Set-Cookie"]
}));

// 3. Updated interface to check for 'sub'
interface CustomJWTPayload extends JWTPayload {
    sub: string;
    id?: string; // Add this
    role?: string;
    isBlocked?: boolean;
}

export interface AuthenticatedRequest extends Request {
    user?: CustomJWTPayload;
}

const client = new MongoClient(uri, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

const JWKS = createRemoteJWKSet(new URL(`${process.env.CLIENT_URL}/api/auth/jwks`));

const verifyToken = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (req.method === 'OPTIONS') return next();

    console.log("Authorization length:", req.headers.authorization?.length);

    console.log(
        "Cookie header length:",
        req.headers.cookie?.length
    );

    const authHeader = req.headers.authorization;

    const token = authHeader?.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : req.cookies?.["better-auth.session_token"];

    if (!token) {
        return res.status(401).json({
            message: "Unauthorized: Missing Token"
        });
    }

    try {
        const { payload } = await jwtVerify(token, JWKS);

        console.log("JWT Payload:", payload);

        const userId = payload.sub;

        if (!userId) {
            return res.status(401).json({
                message: "Invalid token payload."
            });
        }

        const db = client.db("homevault");

        const user = await db.collection("user").findOne({
            _id: ObjectId.isValid(userId)
                ? new ObjectId(userId)
                : userId
        });

        if (!user) {
            return res.status(404).json({
                message: "User not found."
            });
        }

        if (user.isBlocked) {
            return res.status(403).json({
                message: "Your account has been blocked by the administrator."
            });
        }

        // Attach JWT payload + role + isBlocked
        req.user = {
            ...(payload as CustomJWTPayload),
            id: payload.sub, // Map sub to id
            role: user.role,
            isBlocked: user.isBlocked
        } as any;
        next();

    } catch (error: any) {
        console.error(error);

        return res.status(403).json({
            message: "Forbidden: Invalid Token"
        });
    }
};
async function run() {
    try {
        // await client.connect();
        const db: Db = client.db("homevault");
        const usersCollection = db.collection('user');
        // 1. category table
        interface CategoryDocument {
            name: string;
            icon: string;
            image: string;
            shortDescription: string;     // Added
            fullDescription: string;      // Added
            itemTypes: string[];          // Added (Array)
            popularBrands: string[];      // Added (Array)
            organizationTips: string[];   // Added (Array)
            createdBy: string;
            isDefault: boolean;
            isApproved: boolean;
            createdAt: Date;
        }


        const categoriesCollection: Collection<CategoryDocument> = db.collection('categories');
        // 2. Updated POST API Endpoint
        app.post('/api/categories', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const {
                    name,
                    icon,
                    image,
                    shortDescription,
                    fullDescription,
                    itemTypes,
                    popularBrands,
                    organizationTips
                } = req.body;

                const userId = req.user?.id || "unknown";

                if (!name) {
                    return res.status(400).json({
                        success: false,
                        message: "Category name parameter is mandatory."
                    });
                }

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
                    shortDescription: shortDescription || "",
                    fullDescription: fullDescription || "",
                    itemTypes: Array.isArray(itemTypes) ? itemTypes : [],
                    popularBrands: Array.isArray(popularBrands) ? popularBrands : [],
                    organizationTips: Array.isArray(organizationTips) ? organizationTips : [],
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

        // Backend: GET /api/categories
        app.get('/api/categories', async (req: Request, res: Response) => {
            try {
                const { search, categoryName, page: pageQuery, limit: limitQuery } = req.query;
                let filter: any = {};

                if (search) {
                    filter.name = { $regex: search, $options: 'i' };
                }
                if (categoryName && categoryName !== 'all') {
                    filter.name = categoryName;
                }

                // Support fetching all records at once (needed for your frontend's initial filter button list)
                if (limitQuery === 'all') {
                    const categories = await categoriesCollection.find(filter).toArray();
                    return res.status(200).json({
                        success: true,
                        data: categories
                    });
                }

                // Parse pagination values
                const page = parseInt(pageQuery as string) || 1;
                const limit = parseInt(limitQuery as string) || 9;
                const skip = (page - 1) * limit;

                // Fetch data pages and total counts concurrently
                const [categories, totalItems] = await Promise.all([
                    categoriesCollection.find(filter).skip(skip).limit(limit).toArray(),
                    categoriesCollection.countDocuments(filter)
                ]);

                const totalPages = Math.ceil(totalItems / limit);

                return res.status(200).json({
                    success: true,
                    data: categories,
                    pagination: {
                        currentPage: page,
                        totalPages: totalPages || 1,
                        totalItems
                    }
                });
            } catch (error) {
                return res.status(500).json({ success: false, message: "Internal server error." });
            }
        });
        app.get('/api/categories/random', async (req: Request, res: Response) => {
            try {
                // Pulls 3 completely random category documents from the collection
                const randomCategories = await categoriesCollection
                    .aggregate([
                        { $sample: { size: 3 } }
                    ])
                    .toArray();

                return res.status(200).json({
                    success: true,
                    data: randomCategories
                });
            } catch (error) {
                console.error("Error fetching random categories:", error);
                return res.status(500).json({
                    success: false,
                    message: "Failed to fetch top categories."
                });
            }
        });
        app.put('/api/categories/:id', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const { id } = req.params;
                const { name, icon, image, shortDescription, fullDescription, itemTypes, popularBrands, organizationTips } = req.body;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({ success: false, message: "Invalid category ID." });
                }

                // Check if name is being changed to an already existing name
                if (name) {
                    const existing = await categoriesCollection.findOne({
                        name: { $regex: `^${name.trim()}$`, $options: 'i' },
                        _id: { $ne: new ObjectId(id) } // Ensure it's not the same document
                    });
                    if (existing) {
                        return res.status(409).json({ success: false, message: "A category with this name already exists." });
                    }
                }

                const updateData = {
                    ...(name && { name: name.trim() }),
                    icon: icon || "Box",
                    image: image || "",
                    shortDescription: shortDescription || "",
                    fullDescription: fullDescription || "",
                    itemTypes: Array.isArray(itemTypes) ? itemTypes : [],
                    popularBrands: Array.isArray(popularBrands) ? popularBrands : [],
                    organizationTips: Array.isArray(organizationTips) ? organizationTips : [],
                    updatedAt: new Date()
                };

                const result = await categoriesCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updateData }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({ success: false, message: "Category not found." });
                }

                return res.status(200).json({ success: true, message: "Category updated successfully." });

            } catch (error: any) {
                console.error("Error updating category:", error);
                return res.status(500).json({ success: false, message: "Internal server error." });
            }
        });

        // DELETE: Remove a category
        app.delete('/api/categories/:id', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                const { id } = req.params;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({ success: false, message: "Invalid category ID." });
                }

                const result = await categoriesCollection.deleteOne({ _id: new ObjectId(id) });

                if (result.deletedCount === 0) {
                    return res.status(404).json({ success: false, message: "Category not found." });
                }

                return res.status(200).json({ success: true, message: "Category deleted successfully." });

            } catch (error: any) {
                console.error("Error deleting category:", error);
                return res.status(500).json({ success: false, message: "Internal server error." });
            }
        });

        // GET: Single Category (to populate the Edit page form)
        app.get('/api/categories/:id', async (req: Request, res: Response) => {
            try {
                const { id } = req.params;

                // 1. Validate ID format
                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({ success: false, message: "Invalid ID format." });
                }

                // 2. Fetch the category
                // Ensure you are targeting the correct collection
                const category = await categoriesCollection.findOne({ _id: new ObjectId(id) });

                // 3. Handle 404
                if (!category) {
                    return res.status(404).json({ success: false, message: "Category not found." });
                }

                return res.status(200).json({
                    success: true,
                    data: category
                });

            } catch (error) {
                console.error("Error fetching category details:", error);
                return res.status(500).json({ success: false, message: "Internal server error." });
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
        
        // 3. GET API Endpoint: Retrieve Inventory Items (with Category Join)
        app.get('/api/inventory', verifyToken, async (req: any, res: Response) => {
            try {
                const userId = req.user?.id;
                const { categoryId } = req.query;

                if (!userId) {
                    return res.status(401).json({ success: false, message: "Unauthorized." });
                }

                const matchStage: any = { userId: userId };

                if (categoryId) {
                    matchStage.categoryId = categoryId.toString();
                }

                // Using Aggregation Pipeline to join the Category Collection
                const items = await inventoryCollection.aggregate([
                    { $match: matchStage },
                    {
                        $lookup: {
                            from: "categories", // Ensure this matches your actual MongoDB collection name!
                            let: { catIdString: "$categoryId" },
                            pipeline: [
                                {
                                    $match: {
                                        $expr: {
                                            // Converts the stored string ID to ObjectId to match categories._id
                                            $eq: ["$_id", { $toObjectId: "$$catIdString" }]
                                        }
                                    }
                                },
                                // Only pull the title/name fields to keep the response lightweight
                                { $project: { title: 1, name: 1 } }
                            ],
                            as: "categoryInfo"
                        }
                    },
                    {
                        // Flatten the lookup array into a readable field on the inventory object
                        $addFields: {
                            categoryName: {
                                $ifNull: [
                                    { $arrayElemAt: ["$categoryInfo.title", 0] },
                                    { $ifNull: [{ $arrayElemAt: ["$categoryInfo.name", 0] }, "Unknown Category"] }
                                ]
                            }
                        }
                    },
                    {
                        // Clean up the temporary array
                        $project: {
                            categoryInfo: 0
                        }
                    },
                    { $sort: { createdAt: -1 } }
                ]).toArray();

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
        app.put('/api/user/profile', verifyToken, async (req: AuthenticatedRequest, res: Response) => {
            try {
                // 3. Use .sub instead of .id
                const userId = req.user?.sub;
                const { name, image } = req.body;

                if (!userId) {
                    return res.status(401).json({ success: false, message: "Unauthorized profile state adjustment." });
                }

                const queryId = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;

                const updateResult = await db.collection("user").updateOne(
                    { _id: queryId },
                    { $set: { name: name?.trim(), image: image?.trim(), updatedAt: new Date() } }
                );

                if (updateResult.matchedCount === 0) {
                    return res.status(404).json({ success: false, message: "User not found." });
                }

                return res.status(200).json({ success: true, message: "Profile updated." });
            } catch (error) {
                return res.status(500).json({ success: false, message: "Server error." });
            }
        });
        // GET: Fetch all users (Admin only)
        app.get("/api/admin/users", verifyToken, async (req: any, res: any) => {
            if (req.user?.role !== "admin") return res.status(403).json({ success: false });

            const users = await db.collection("user").find({}).project({ password: 0 }).toArray();
            res.json({ success: true, data: users });
        });

        app.patch("/api/admin/users/:id/block", verifyToken, async (req: any, res: any) => {
            if (req.user?.role !== "admin") return res.status(403).json({ success: false });

            await db.collection("user").updateOne(
                { _id: new ObjectId(req.params.id) },
                { $set: { isBlocked: req.body.isBlocked } }
            );
            res.json({ success: true });
        });


        // Assuming you have an authentication middleware that populates req.user
        app.get('/api/dashboard/stats', verifyToken, async (req: Request, res: Response) => {
            try {
                // 1. Extract and convert userId from the authenticated session/token
                const userIdString = (req as any).user?.id || (req as any).user?._id;

                if (!userIdString) {
                    return res.status(401).json({ success: false, message: "Unauthorized. No session found." });
                }

                // Ensure we match MongoDB ObjectId if stored as ObjectId, or string if stored as string
                const userFilter = ObjectId.isValid(userIdString)
                    ? { $in: [new ObjectId(userIdString), userIdString] }
                    : userIdString;

                const baseMatch = { userId: userFilter };

                // 2. Calculate "Start of This Month" for recent metric
                const now = new Date();
                const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

                // 3. Run parallel aggregations for maximum performance
                const [
                    basicStats,
                    itemsByCategory,
                    itemsByRoom,
                    monthlyGrowth,
                    recentActivity
                ] = await Promise.all([
                    // A. Total Items, Total Value, Categories Used, Added This Month
                    inventoryCollection.aggregate([
                        { $match: { userId: userFilter } },
                        {
                            $group: {
                                _id: null,
                                totalItems: { $sum: 1 },
                                estimatedValue: { $sum: { $toDouble: "$estimatedValue" } },
                                uniqueCategories: { $addToSet: "$categoryId" },
                                itemsThisMonth: {
                                    $sum: {
                                        $cond: [{ $gte: ["$createdAt", startOfMonth] }, 1, 0]
                                    }
                                }
                            }
                        },
                        {
                            $project: {
                                totalItems: 1,
                                estimatedValue: 1,
                                categoriesUsed: { $size: "$uniqueCategories" },
                                itemsThisMonth: 1
                            }
                        }
                    ]).toArray(),

                    // B. Chart: Items by Category (Joining with Categories table to get names)
                    // B. Chart: Items by Category
                    inventoryCollection.aggregate([
                        { $match: { userId: userFilter } },
                        {
                            $group: {
                                _id: "$categoryId",
                                count: { $sum: 1 }
                            }
                        },
                        {
                            $lookup: {
                                from: "categories",
                                let: { catId: "$_id" },
                                pipeline: [
                                    {
                                        $match: {
                                            $expr: {
                                                $eq: ["$_id", { $toObjectId: "$$catId" }] // Converts string ID to ObjectId for matching
                                            }
                                        }
                                    }
                                ],
                                as: "categoryInfo"
                            }
                        },
                        {
                            $project: {
                                name: { $ifNull: [{ $arrayElemAt: ["$categoryInfo.name", 0] }, "Uncategorized"] },
                                value: "$count"
                            }
                        }
                    ]).toArray(),

                    // C. Chart: Items by Room
                    inventoryCollection.aggregate([
                        { $match: { userId: userFilter } },
                        {
                            $group: {
                                _id: { $ifNull: ["$room", "Unassigned"] },
                                count: { $sum: 1 }
                            }
                        }, {
                            $project: {
                                room: "$_id",
                                count: 1,
                                _id: 0
                            }
                        },
                        { $sort: { count: -1 } }, { $limit: 6 } // Top 6 rooms
                    ]).toArray(),

                    // D. Chart: Items Added Monthly (Last 6 Months)
                    inventoryCollection.aggregate([
                        { $match: { userId: userFilter } },
                        {
                            $group: {
                                _id: {
                                    year: { $year: "$createdAt" },
                                    month: { $month: "$createdAt" }
                                },
                                count: { $sum: 1 }
                            }
                        }, { $sort: { "_id.year": 1, "_id.month": 1 } },
                        { $limit: 6 }, {
                            $project: {
                                month: {
                                    $concat: [
                                        { $toString: "$_id.month" }, "/", { $toString: "$_id.year" }
                                    ]
                                },
                                items: "$count",
                                _id: 0
                            }
                        }
                    ]).toArray(),

                    // E. Recent Activity (Last 5 modified/created items)
                    inventoryCollection.find({ userId: userFilter })
                        .sort({ createdAt: -1 })
                        .limit(5)
                        .project({ title: 1, brand: 1, room: 1, createdAt: 1, condition: 1 })
                        .toArray()
                ]);

                // Format and send response
                const stats = basicStats[0] || { totalItems: 0, estimatedValue: 0, categoriesUsed: 0, itemsThisMonth: 0 };

                return res.status(200).json({
                    success: true,
                    data: {
                        cards: stats,
                        charts: {
                            itemsByCategory,
                            itemsByRoom,
                            monthlyGrowth
                        },
                        recentActivity
                    }
                });

            } catch (error) {
                console.error("Dashboard Stats Error:", error);
                return res.status(500).json({ success: false, message: "Failed to fetch dashboard metrics." });
            }
        });
        app.get('/api/admin/dashboard/stats', verifyToken, async (req: Request, res: Response) => {
            try {
                // 1. Strict Authorization Check
                const isAdmin = (req as any).user?.role === 'admin';
                if (!isAdmin) {
                    return res.status(403).json({ success: false, message: "Access denied. Admins only." });
                }

                const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

                // 2. Run parallel aggregations across the entire database for global admin stats
                const [
                    totalUsers,
                    totalCategories,
                    totalInventoryItems,
                    defaultCategories,
                    inventoryDistributionRaw,
                    userGrowthRaw,
                    itemsAddedRaw,
                    latestUsers,
                    latestCategories,
                    latestInventory
                ] = await Promise.all([
                    // Core Total Counts (Global Scope)
                    usersCollection.countDocuments(),
                    categoriesCollection.countDocuments(),
                    inventoryCollection.countDocuments(),
                    categoriesCollection.countDocuments({ isDefault: true }),

                    // Pie Chart: Inventory Items grouped by Category ID + Resilient Name Lookup
                    inventoryCollection.aggregate([
                        { $match: { categoryId: { $exists: true, $ne: null } } },
                        {
                            $group: {
                                _id: "$categoryId",
                                count: { $sum: 1 }
                            }
                        },
                        {
                            $lookup: {
                                from: "categories",
                                let: { catId: "$_id" },
                                pipeline: [
                                    {
                                        $match: {
                                            $expr: {
                                                $eq: [
                                                    "$_id",
                                                    {
                                                        $cond: {
                                                            if: { $eq: [{ $type: "$$catId" }, "string"] },
                                                            then: { $toObjectId: "$$catId" },
                                                            else: "$$catId"
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                ],
                                as: "categoryDetails"
                            }
                        },
                        {
                            $project: {
                                name: { $ifNull: [{ $arrayElemAt: ["$categoryDetails.name", 0] }, "Uncategorized"] },
                                value: "$count",
                                _id: 0
                            }
                        }
                    ]).toArray(),

                    // Bar Chart: Global User Registrations (Corrected for Latest 6 Months)
                    usersCollection.aggregate([
                        { $match: { createdAt: { $exists: true, $ne: null } } },
                        {
                            $group: {
                                _id: {
                                    year: { $year: { $toDate: "$createdAt" } },
                                    month: { $month: { $toDate: "$createdAt" } }
                                },
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { "_id.year": -1, "_id.month": -1 } }, // Grab the most recent months first
                        { $limit: 6 },
                        { $sort: { "_id.year": 1, "_id.month": 1 } }   // Re-sort chronologically for UI chart layout
                    ]).toArray(),

                    // Line Chart: Global Inventory Additions Timeline (Corrected for Latest 6 Months)
                    inventoryCollection.aggregate([
                        { $match: { createdAt: { $exists: true, $ne: null } } },
                        {
                            $group: {
                                _id: {
                                    year: { $year: { $toDate: "$createdAt" } },
                                    month: { $month: { $toDate: "$createdAt" } }
                                },
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { "_id.year": -1, "_id.month": -1 } }, // Grab the most recent months first
                        { $limit: 6 },
                        { $sort: { "_id.year": 1, "_id.month": 1 } }   // Re-sort chronologically for UI chart layout
                    ]).toArray(),

                    // Recent System Activity Pulls (Last 3 entries from each collection)
                    usersCollection.find({}).sort({ createdAt: -1 }).limit(3).toArray(),
                    categoriesCollection.find({}).sort({ createdAt: -1 }).limit(3).toArray(),
                    inventoryCollection.find({}).sort({ createdAt: -1 }).limit(3).toArray()
                ]);

                // 3. Format Chronological Growth Labels safely
                const userGrowth = userGrowthRaw.map(item => ({
                    month: item._id ? (monthNames[item._id.month - 1] || `${item._id.month}/${item._id.year}`) : "Unknown",
                    count: item.count
                }));

                const itemsAdded = itemsAddedRaw.map(item => ({
                    month: item._id ? (monthNames[item._id.month - 1] || `${item._id.month}/${item._id.year}`) : "Unknown",
                    count: item.count
                }));

                // 4. Construct unified dynamic Activity Feed
                const activities: any[] = [];

                latestUsers.forEach(u => {
                    activities.push({
                        id: `user_${u._id}`,
                        type: 'user',
                        message: `${u.name || 'A new user'} joined the system.`,
                        createdAt: u.createdAt
                    });
                });

                latestCategories.forEach(c => {
                    activities.push({
                        id: `cat_${c._id}`,
                        type: 'category',
                        message: `${c.createdBy === 'admin' ? 'Admin' : 'A user'} created the "${c.name}" category.`,
                        createdAt: c.createdAt
                    });
                });

                latestInventory.forEach(i => {
                    activities.push({
                        id: `inv_${i._id}`,
                        type: 'inventory',
                        message: `An item "${i.title}" was added to the ${i.room || 'Storage'}.`,
                        createdAt: i.createdAt
                    });
                });

                // Sort compilation array globally by real-time timestamps
                const sortedActivityFeed = activities
                    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
                    .slice(0, 5);

                // 5. Response Pipeline Delivery
                return res.status(200).json({
                    success: true,
                    data: {
                        cards: {
                            totalUsers,
                            totalCategories,
                            totalInventoryItems,
                            defaultCategories
                        },
                        charts: {
                            inventoryDistribution: inventoryDistributionRaw,
                            userGrowth,
                            itemsAdded
                        },
                        recentActivity: sortedActivityFeed
                    }
                });

            } catch (error) {
                console.error("Dashboard Global Aggregation Failure:", error);
                return res.status(500).json({
                    success: false,
                    message: "Internal server error: Failed to fetch admin metrics dashboard data cleanly."
                });
            }
        });
        app.get('/api/stats/platform', async (req: Request, res: Response) => {
            try {
                // Run all platform-wide aggregation and document count tasks concurrently
                const [
                    totalCategories,
                    totalItems,
                    totalUsers,
                    defaultCategories,
                    customCategories,
                    valueAggregation
                ] = await Promise.all([
                    categoriesCollection.countDocuments(),
                    inventoryCollection.countDocuments(),
                    usersCollection.countDocuments({ role: "user" }),
                    categoriesCollection.countDocuments({ isDefault: true }),
                    categoriesCollection.countDocuments({ isDefault: false }),
                    inventoryCollection.aggregate([
                        {
                            $group: {
                                _id: null,
                                total: { $sum: { $toDouble: "$purchasePrice" } }
                            }
                        }
                    ]).toArray()
                ]);

                // Extract total aggregated price safely, default to 0 if inventory is empty
                const totalInventoryValue = valueAggregation[0]?.total || 0;

                return res.status(200).json({
                    success: true,
                    data: {
                        totalCategories,
                        totalItems,
                        totalUsers,
                        defaultCategories,
                        customCategories,
                        totalInventoryValue
                    }
                });
            } catch (error) {
                console.error("Error generating platform metrics:", error);
                return res.status(500).json({
                    success: false,
                    message: "Failed to compile platform metrics."
                });
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