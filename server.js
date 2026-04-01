const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const path = require('path'); 
const multer = require('multer'); 
const cloudinary = require('cloudinary').v2; // NEW: Cloudinary
const { CloudinaryStorage } = require('multer-storage-cloudinary'); // NEW: Cloudinary Storage
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key_123';

// --- 1. Middleware ---
app.use(helmet({
  crossOriginResourcePolicy: false, 
}));

app.use(express.json({ limit: '50mb' })); 
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// --- 2. Cloudinary & Multer Configuration (File Uploads) ---

// Configure Cloudinary with your .env credentials
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Set up Cloudinary Storage for Multer
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'fashion_store_products', // The folder name in your Cloudinary media library
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
  },
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 1024 * 1024 * 5 } // 5MB limit
});


// --- 3. Database Connection ---
const connectDB = async () => {
    try {
        const mongoURI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/fashionStoreDB';
        await mongoose.connect(mongoURI);
        console.log("✅ MongoDB Connected Successfully");
    } catch (err) {
        console.error("❌ MongoDB Connection Error:", err.message);
        process.exit(1);
    }
};
connectDB();

// --- 4. Schemas & Models ---

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    phone: { type: String, default: "" },
    addresses: [{
        name: String, street: String, city: String, state: String, zip: String
    }],
    wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
    isAdmin: { type: Boolean, default: false }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
    name: { type: String, required: true, index: true },
    price: { type: Number, required: true },
    category: { type: String, required: true, enum: ['Men', 'Women', 'Kids'], index: true },
    subCategory: { type: String, enum: ['Boys', 'Girls', 'Unisex', 'None'], default: 'None' },
    stock: { type: Number, default: 0 }, 
    image: { type: String }, 
    images: { type: [String], default: [] }, 
    description: { type: String },
    sizes: { type: [mongoose.Schema.Types.Mixed], default: [] },
    rating: { type: Number, required: true, default: 0 },
    numReviews: { type: Number, required: true, default: 0 },
    reviews: [{ 
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        userName: { type: String, required: true }, 
        rating: { type: Number, required: true }, 
        comment: { type: String, required: true }, 
        createdAt: { type: Date, default: Date.now }
    }]
}, { timestamps: true });

const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
    userEmail: { type: String, required: true },
    userName: { type: String },
    amount: { type: Number, required: true },
    status: { type: String, default: 'Pending', enum: ['Pending', 'Packed', 'Shipped', 'Delivered', 'Return Requested', 'Refunded', 'Cancelled'] },
    returnReason: { type: String },
    deliveredAt: { type: Date }, 
    items: [{
        productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
        name: { type: String, required: true },
        image: { type: String, required: true }, 
        quantity: { type: Number, required: true },
        price: { type: Number, required: true },
        size: { type: String, required: true }
    }],
    orderDate: { type: Date, default: Date.now }
}, { timestamps: true });

const Order = mongoose.model('Order', orderSchema);

const cartSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [{
        productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
        name: String,
        price: Number,
        image: String,
        size: String,
        quantity: { type: Number, required: true, min: 1, default: 1 }
    }],
    totalPrice: { type: Number, required: true, default: 0 }
}, { timestamps: true });

const Cart = mongoose.model('Cart', cartSchema);

const newsletterSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true }
}, { timestamps: true });

const Newsletter = mongoose.model('Newsletter', newsletterSchema);

// --- 5. Middlewares ---

const protect = async (req, res, next) => {
    let token;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer')) {
        try {
            token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            
            if (decoded.id === '650000000000000000000000') {
                req.user = { _id: '650000000000000000000000', isAdmin: true, email: 'admin@gmail.com', name: 'System Admin' };
                return next();
            }

            req.user = await User.findById(decoded.id).select('-password');
            if (!req.user) return res.status(401).json({ message: "User no longer exists" });
            next();
        } catch (error) {
            return res.status(401).json({ message: "Not authorized" });
        }
    } else {
        return res.status(401).json({ message: "No token provided" });
    }
};

const adminOnly = (req, res, next) => {
    if (req.user && req.user.isAdmin) next();
    else res.status(403).json({ message: "Access denied: Admins only" });
};

const generateToken = (id, isAdmin) => jwt.sign({ id, isAdmin }, JWT_SECRET, { expiresIn: '24h' });

// --- 6. Routes ---

// AUTH
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const userExists = await User.findOne({ email });
        if (userExists) return res.status(400).json({ message: "User already exists" });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = await User.create({ name, email, password: hashedPassword });
        
        await Cart.create({ user: newUser._id, items: [], totalPrice: 0 });

        res.status(201).json({ 
            token: generateToken(newUser._id, newUser.isAdmin), 
            user: { id: newUser._id, name: newUser.name, email: newUser.email, isAdmin: newUser.isAdmin } 
        });
    } catch (err) { res.status(500).json({ message: "Registration failed" }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (email === "admin@gmail.com" && password === "admin123") {
            const adminId = '650000000000000000000000';
            return res.json({ 
                token: generateToken(adminId, true), 
                user: { id: adminId, name: "System Admin", email: "admin@gmail.com", isAdmin: true } 
            });
        }

        const user = await User.findOne({ email });
        if (user && (await bcrypt.compare(password, user.password))) {
            res.json({ 
                token: generateToken(user._id, user.isAdmin), 
                user: { id: user._id, name: user.name, email: user.email, isAdmin: user.isAdmin } 
            });
        } else {
            res.status(401).json({ message: "Invalid email or password" });
        }
    } catch (err) { res.status(500).json({ message: "Login failed" }); }
});

// PROFILE
app.get('/api/users/profile', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password');
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.json(user);
    } catch (err) { 
        console.error("Profile Fetch Error:", err);
        res.status(500).json({ message: "Failed to fetch profile" }); 
    }
});

app.put('/api/users/profile', protect, async (req, res) => {
    try {
        const updatedUser = await User.findByIdAndUpdate(req.user._id, req.body, { returnDocument: 'after' }).select('-password');
        res.json(updatedUser);
    } catch (err) { res.status(400).json({ message: "Update failed" }); }
});

// WISHLIST
app.get('/api/wishlist', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).populate('wishlist');
        res.json(user.wishlist);
    } catch (err) { res.status(500).json({ message: "Fetch wishlist failed" }); }
});

app.post('/api/wishlist', protect, async (req, res) => {
    try {
        const { productId } = req.body;
        const user = await User.findById(req.user._id);
        if (!user.wishlist.includes(productId)) {
            user.wishlist.push(productId);
            await user.save();
        }
        res.status(201).json({ message: "Added to wishlist" });
    } catch (err) { res.status(400).json({ message: "Wishlist update failed" }); }
});

app.delete('/api/wishlist/:productId', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        user.wishlist = user.wishlist.filter(id => id.toString() !== req.params.productId);
        await user.save();
        res.json({ message: "Item removed from wishlist" });
    } catch (err) { 
        res.status(500).json({ message: "Failed to remove item" }); 
    }
});

// PRODUCTS
app.get('/api/products', async (req, res) => {
    try {
        const { category, subCategory, search } = req.query; 
        
        let query = {};
        if (category && category !== 'All') query.category = category;
        if (subCategory && subCategory !== 'All') query.subCategory = subCategory; 
        if (search) query.name = { $regex: search, $options: 'i' };
        
        const products = await Product.find(query).sort({ createdAt: -1 });
        res.json(products);
    } catch (err) { res.status(500).json({ message: "Fetch products failed" }); }
});

// --- REVIEWS CRUD ---
app.post('/api/products/:id/reviews', protect, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const product = await Product.findById(req.params.id);

        if (product) {
            const alreadyReviewed = product.reviews.find(
                (r) => r.user.toString() === req.user._id.toString()
            );

            if (alreadyReviewed) {
                return res.status(400).json({ message: "You have already reviewed this product." });
            }

            const review = {
                user: req.user._id,
                userName: req.user.name,
                rating: Number(rating),
                comment,
            };

            product.reviews.push(review);
            product.numReviews = product.reviews.length;
            product.rating = product.reviews.reduce((acc, item) => item.rating + acc, 0) / product.reviews.length;

            await product.save();
            res.status(201).json({ message: "Review added successfully!" });
        } else {
            res.status(404).json({ message: "Product not found" });
        }
    } catch (err) { 
        res.status(500).json({ message: "Failed to submit review" }); 
    }
});

app.put('/api/products/:id/reviews/:reviewId', protect, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const product = await Product.findById(req.params.id);

    if (!product) return res.status(404).json({ message: 'Product not found' });

    const review = product.reviews.id(req.params.reviewId);
    if (!review) return res.status(404).json({ message: 'Review not found' });

    if (review.user.toString() !== req.user._id.toString()) {
      return res.status(401).json({ message: 'User not authorized to edit this review' });
    }

    review.rating = Number(rating);
    review.comment = comment;

    product.rating = product.reviews.reduce((acc, item) => item.rating + acc, 0) / product.reviews.length;

    await product.save();
    res.json({ message: 'Review updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server Error' });
  }
});

app.delete('/api/products/:id/reviews/:reviewId', protect, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);

    if (!product) return res.status(404).json({ message: 'Product not found' });

    const review = product.reviews.id(req.params.reviewId);
    if (!review) return res.status(404).json({ message: 'Review not found' });

    if (review.user.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      return res.status(401).json({ message: 'User not authorized to delete this review' });
    }

    product.reviews.pull(req.params.reviewId);
    product.numReviews = product.reviews.length;

    if (product.numReviews > 0) {
      product.rating = product.reviews.reduce((acc, item) => item.rating + acc, 0) / product.numReviews;
    } else {
      product.rating = 0; 
    }

    await product.save();
    res.json({ message: 'Review deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server Error' });
  }
});

// --- ADMIN PRODUCT CRUD (UPDATED FOR CLOUDINARY) ---

app.post('/api/products', protect, adminOnly, upload.array('images', 5), async (req, res) => {
    try {
        const productData = {
          ...req.body,
          sizes: req.body.sizes ? JSON.parse(req.body.sizes) : []
        };
        
        if (req.files && req.files.length > 0) {
          // Cloudinary provides the secure URL directly in 'file.path'
          const imagePaths = req.files.map(file => file.path);
          productData.image = imagePaths[0]; 
          productData.images = imagePaths;   
        } else {
          productData.image = "";
          productData.images = [];
        }

        const product = await Product.create(productData);
        res.status(201).json(product);
    } catch (err) { 
        res.status(400).json({ message: err.message || "Creation failed" }); 
    }
});

app.put('/api/products/:id', protect, adminOnly, upload.array('images', 5), async (req, res) => {
    try {
        const updateData = {
          ...req.body,
          sizes: req.body.sizes ? JSON.parse(req.body.sizes) : []
        };

        const existingImages = req.body.existingImages 
            ? (Array.isArray(req.body.existingImages) ? req.body.existingImages : [req.body.existingImages]) 
            : [];
        
        // Map new files from Cloudinary using file.path
        const newImagePaths = req.files ? req.files.map(file => file.path) : [];
        const finalImagesArray = [...existingImages, ...newImagePaths];

        if (finalImagesArray.length > 0) {
          updateData.image = finalImagesArray[0];
          updateData.images = finalImagesArray;
        } else {
          updateData.image = "";
          updateData.images = [];
        }

        const updated = await Product.findByIdAndUpdate(req.params.id, updateData, { returnDocument: 'after' });
        res.json(updated);
    } catch (err) { 
        res.status(400).json({ message: err.message || "Update failed" }); 
    }
});

app.delete('/api/products/:id', protect, adminOnly, async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: "Product deleted" });
    } catch (err) { res.status(500).json({ message: "Delete failed" }); }
});

// PERSISTENT CART ROUTES
app.get('/api/cart', protect, async (req, res) => {
    try {
        let cart = await Cart.findOne({ user: req.user._id });
        if (!cart) cart = await Cart.create({ user: req.user._id, items: [], totalPrice: 0 });
        res.json(cart);
    } catch (err) { res.status(500).json({ message: "Fetch cart failed" }); }
});

app.post('/api/cart', protect, async (req, res) => {
    try {
        const { productId, name, price, image, size, quantity } = req.body;
        let cart = await Cart.findOne({ user: req.user._id });
        if (!cart) cart = new Cart({ user: req.user._id, items: [], totalPrice: 0 });

        const itemIndex = cart.items.findIndex(p => p.productId.toString() === productId && p.size === size);
        if (itemIndex > -1) cart.items[itemIndex].quantity += quantity;
        else cart.items.push({ productId, name, price, image, size, quantity });

        cart.totalPrice = cart.items.reduce((acc, item) => acc + (item.price * item.quantity), 0);
        await cart.save();
        res.status(200).json(cart);
    } catch (err) { res.status(400).json({ message: "Add to cart failed" }); }
});

app.put('/api/cart/update', protect, async (req, res) => {
    try {
        const { productId, size, quantity } = req.body;
        let cart = await Cart.findOne({ user: req.user._id });
        if (!cart) return res.status(404).json({ message: "Cart not found" });

        const itemIndex = cart.items.findIndex(p => p.productId.toString() === productId && p.size === size);
        
        if (itemIndex > -1) {
            cart.items[itemIndex].quantity = quantity; 
            cart.totalPrice = cart.items.reduce((acc, item) => acc + (item.price * item.quantity), 0);
            await cart.save();
            return res.status(200).json(cart);
        }
        res.status(404).json({ message: "Item not found in cart" });
    } catch (err) { 
        res.status(500).json({ message: "Update cart failed" }); 
    }
});

app.delete('/api/cart/item/:productId/:size', protect, async (req, res) => {
    try {
        let cart = await Cart.findOne({ user: req.user._id });
        if (!cart) return res.status(404).json({ message: "Cart not found" });
        
        cart.items = cart.items.filter(item => 
            !(item.productId.toString() === req.params.productId && item.size === req.params.size)
        );
        
        cart.totalPrice = cart.items.reduce((acc, item) => acc + (item.price * item.quantity), 0);
        await cart.save();
        res.json(cart);
    } catch (err) { 
        res.status(500).json({ message: "Remove from cart failed" }); 
    }
});

app.delete('/api/cart', protect, async (req, res) => {
    try {
        let cart = await Cart.findOne({ user: req.user._id });
        if (!cart) return res.status(404).json({ message: "Cart not found" });

        cart.items = [];
        cart.totalPrice = 0;
        
        await cart.save();
        res.json({ message: "Cart cleared successfully", cart });
    } catch (err) { 
        res.status(500).json({ message: "Clear cart failed" }); 
    }
});

// ORDERS
app.post('/api/orders', protect, async (req, res) => {
    try {
        const orderItems = req.body.items || req.body.orderItems || req.body.checkoutItems;
        const orderAmount = req.body.amount || req.body.totalPrice || req.body.checkoutTotal; 

        if (!orderItems || !Array.isArray(orderItems) || orderItems.length === 0) {
            return res.status(400).json({ message: "Payload Error: No items received by the backend." });
        }
        
        const formattedItems = orderItems.map(item => ({
            productId: item.productId || item._id,
            name: item.name,
            image: item.image,
            price: Number(item.price),
            quantity: Number(item.quantity || item.qty),
            size: item.size || item.selectedSize || "N/A"
        }));

        for (const item of formattedItems) {
            const product = await Product.findById(item.productId);
            if (!product) {
                return res.status(404).json({ message: `Product not found: ${item.name}` });
            }
            
            if (product.sizes && product.sizes.length > 0 && typeof product.sizes[0] === 'object') {
                const sizeData = product.sizes.find(s => s.size === item.size);
                
                if (!sizeData || sizeData.countInStock < item.quantity) {
                    return res.status(400).json({ 
                        message: `Out of Stock: We only have ${sizeData ? sizeData.countInStock : 0} left in size ${item.size} for ${product.name}` 
                    });
                }
                await Product.updateOne(
                    { _id: item.productId, "sizes.size": item.size },
                    { $inc: { "sizes.$.countInStock": -item.quantity } }
                );
            } else {
                if (product.stock < item.quantity) {
                    return res.status(400).json({ 
                        message: `Out of Stock: We only have ${product.stock} left for ${product.name}` 
                    });
                }
                await Product.updateOne(
                    { _id: item.productId },
                    { $inc: { stock: -item.quantity } }
                );
            }
        }

        const order = await Order.create({ 
            user: req.user._id, 
            userEmail: req.user.email, 
            userName: req.user.name,   
            amount: orderAmount, 
            items: formattedItems 
        });

        await Cart.findOneAndUpdate({ user: req.user._id }, { items: [], totalPrice: 0 }, { returnDocument: 'after' });
        
        res.status(201).json(order);
    } catch (err) { 
        res.status(400).json({ message: err.message || "Order placement failed" }); 
    }
});

app.get('/api/orders/myorders', protect, async (req, res) => {
    try {
        const orders = await Order.find({ user: req.user._id }).sort({ createdAt: -1 });
        res.json(orders);
    } catch (err) { res.status(500).json({ message: "Fetch orders failed" }); }
});

app.put('/api/orders/:id/action', protect, async (req, res) => {
    try {
        const { action, reason } = req.body; 
        const order = await Order.findById(req.params.id);
        
        if (!order || order.user.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: "Unauthorized action." });
        }

        if (action === 'cancel') {
            if (['Shipped', 'Delivered', 'Return Requested', 'Refunded', 'Cancelled'].includes(order.status)) {
                return res.status(400).json({ message: "Order cannot be cancelled at this stage." });
            }
            order.status = 'Cancelled';
            
            for (const item of order.items) {
                const product = await Product.findById(item.productId);
                if (product) {
                    if (product.sizes && product.sizes.length > 0 && typeof product.sizes[0] === 'object') {
                        const sizeExists = product.sizes.some(s => s.size === item.size);
                        if (sizeExists) {
                            await Product.updateOne(
                                { _id: item.productId, "sizes.size": item.size },
                                { $inc: { "sizes.$.countInStock": item.quantity } }
                            );
                        } else {
                            await Product.updateOne(
                                { _id: item.productId },
                                { $push: { sizes: { size: item.size, countInStock: item.quantity } } }
                            );
                        }
                    } else {
                        await Product.updateOne(
                            { _id: item.productId },
                            { $inc: { stock: item.quantity } }
                        );
                    }
                }
            }
        } else if (action === 'return') {
            if (order.status !== 'Delivered') {
                return res.status(400).json({ message: "Order must be delivered to be eligible for a return." });
            }
            
            // Critical fix: Ensure there's a fallback if deliveredAt is null 
            const deliveryDate = order.deliveredAt || order.updatedAt;
            const daysSinceDelivery = (Date.now() - new Date(deliveryDate).getTime()) / (1000 * 60 * 60 * 24);

            if (daysSinceDelivery > 7) {
                return res.status(400).json({ message: "The 7-day return window has expired." });
            }
            
            order.status = 'Return Requested';
            if (reason) order.returnReason = reason;
        }

        await order.save();
        res.json(order);
    } catch (err) { 
        res.status(500).json({ message: "Action failed due to server error." }); 
    }
});

// ADMIN MANAGEMENT & ANALYTICS
app.get('/api/admin/stats', protect, adminOnly, async (req, res) => {
    try {
        const [totalUsers, totalProducts, orders] = await Promise.all([
            User.countDocuments(),
            Product.countDocuments(),
            Order.find({})
        ]);
        const totalRevenue = orders.reduce((acc, curr) => !['Refunded', 'Cancelled'].includes(curr.status) ? acc + (Number(curr.amount) || 0) : acc, 0);
        res.json({ totalUsers, totalProducts, totalOrders: orders.length, totalRevenue });
    } catch (err) { res.status(500).json({ message: "Stats fetch failed" }); }
});

app.get('/api/admin/users', protect, adminOnly, async (req, res) => {
    const users = await User.find({}).select('-password').sort({ createdAt: -1 });
    res.json(users);
});

app.delete('/api/admin/users/:id', protect, adminOnly, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user || user.isAdmin) return res.status(400).json({ message: "Cannot delete an Admin account." });
        
        await Cart.findOneAndDelete({ user: req.params.id });
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: "User permanently removed." });
    } catch (err) { res.status(500).json({ message: "Delete failed" }); }
});

app.get('/api/admin/orders', protect, adminOnly, async (req, res) => {
    const orders = await Order.find({}).sort({ createdAt: -1 });
    res.json(orders);
});

app.put('/api/admin/orders/:id/status', protect, adminOnly, async (req, res) => {
    try {
        const { status, returnReason } = req.body;
        const order = await Order.findById(req.params.id);
        if (!order) return res.status(404).json({ message: "Order not found" });

        if (status === "Delivered" && order.status !== "Delivered") order.deliveredAt = Date.now();
        
        if (['Refunded', 'Cancelled'].includes(status) && !['Refunded', 'Cancelled'].includes(order.status)) {
            for (const item of order.items) {
                const product = await Product.findById(item.productId);
                if (product) {
                    if (product.sizes && product.sizes.length > 0 && typeof product.sizes[0] === 'object') {
                        const sizeExists = product.sizes.some(s => s.size === item.size);
                        if (sizeExists) {
                            await Product.updateOne(
                                { _id: item.productId, "sizes.size": item.size },
                                { $inc: { "sizes.$.countInStock": item.quantity } }
                            );
                        } else {
                            await Product.updateOne(
                                { _id: item.productId },
                                { $push: { sizes: { size: item.size, countInStock: item.quantity } } }
                            );
                        }
                    } else {
                        await Product.updateOne(
                            { _id: item.productId },
                            { $inc: { stock: item.quantity } }
                        );
                    }
                }
            }
        }
        
        order.status = status;
        if (returnReason) order.returnReason = returnReason;
        await order.save();
        res.json(order);
    } catch (err) { res.status(400).json({ message: "Status update failed" }); }
});

// NEWSLETTER
app.post('/api/newsletter', async (req, res) => {
    try {
        await Newsletter.create({ email: req.body.email });
        res.status(201).json({ message: "Subscribed" });
    } catch (err) { res.status(400).json({ message: "Already subscribed" }); }
});

app.get('/api/admin/newsletter', protect, adminOnly, async (req, res) => {
    const subs = await Newsletter.find().sort({ createdAt: -1 });
    res.json(subs);
});

// --- 7. Global Error Handling ---
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: "Internal Server Error" });
});

app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));