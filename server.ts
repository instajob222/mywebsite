import express from 'express';
import { createServer as createViteServer } from 'vite';
import Database from 'better-sqlite3';
import { GoogleGenAI } from '@google/genai';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-for-dev';

app.use(express.json({ limit: '10mb' }));

// Initialize Database
const db = new Database('ecommerce.db');

// Create Tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    store_name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    sku TEXT,
    barcode TEXT,
    price REAL NOT NULL,
    cost REAL NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0,
    category TEXT,
    brand TEXT,
    weight TEXT,
    dimensions TEXT,
    image_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, sku)
  );

  CREATE TABLE IF NOT EXISTS product_variants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    sku TEXT,
    price REAL NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    address TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, email)
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    customer_id INTEGER,
    status TEXT NOT NULL DEFAULT 'Pending',
    total_amount REAL NOT NULL,
    shipping_cost REAL DEFAULT 0,
    courier TEXT,
    tracking_number TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
  );

  CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER,
    product_id INTEGER,
    variant_id INTEGER,
    quantity INTEGER NOT NULL,
    price REAL NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (variant_id) REFERENCES product_variants(id)
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL, -- 'Income' or 'Expense'
    amount REAL NOT NULL,
    description TEXT,
    date DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS user_settings (
    user_id INTEGER,
    key TEXT,
    value TEXT NOT NULL,
    PRIMARY KEY (user_id, key),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Migration for multi-tenancy
const tableInfo = db.prepare("PRAGMA table_info(products)").all() as any[];
if (!tableInfo.some(col => col.name === 'user_id')) {
  console.log("Migrating database to multi-tenant...");
  
  let defaultUserId;
  const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@storesync.com') as any;
  if (existingUser) {
    defaultUserId = existingUser.id;
  } else {
    const defaultHash = bcrypt.hashSync('password123', 10);
    const info = db.prepare('INSERT INTO users (email, password_hash, store_name) VALUES (?, ?, ?)').run('admin@storesync.com', defaultHash, 'Default Store');
    defaultUserId = info.lastInsertRowid;
  }

  db.exec(`
    PRAGMA foreign_keys=OFF;

    -- Products
    DROP TABLE IF EXISTS products_new;
    CREATE TABLE products_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL DEFAULT ${defaultUserId},
      name TEXT NOT NULL,
      description TEXT,
      sku TEXT,
      barcode TEXT,
      price REAL NOT NULL,
      cost REAL NOT NULL,
      stock INTEGER NOT NULL DEFAULT 0,
      category TEXT,
      brand TEXT,
      weight TEXT,
      dimensions TEXT,
      image_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, sku)
    );
    INSERT INTO products_new (id, name, description, sku, barcode, price, cost, stock, category, brand, weight, dimensions, image_url, created_at)
    SELECT id, name, description, sku, barcode, price, cost, stock, category, NULL, NULL, NULL, image_url, created_at FROM products;
    DROP TABLE products;
    ALTER TABLE products_new RENAME TO products;

    -- Customers
    DROP TABLE IF EXISTS customers_new;
    CREATE TABLE customers_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL DEFAULT ${defaultUserId},
      name TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      address TEXT,
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, email)
    );
    INSERT INTO customers_new (id, name, email, phone, address, notes, created_at)
    SELECT id, name, email, phone, address, notes, created_at FROM customers;
    DROP TABLE customers;
    ALTER TABLE customers_new RENAME TO customers;

    -- Orders
    ALTER TABLE orders ADD COLUMN user_id INTEGER DEFAULT ${defaultUserId};
    
    -- Transactions
    ALTER TABLE transactions ADD COLUMN user_id INTEGER DEFAULT ${defaultUserId};

    -- Settings
    CREATE TABLE IF NOT EXISTS user_settings (
      user_id INTEGER,
      key TEXT,
      value TEXT NOT NULL,
      PRIMARY KEY (user_id, key),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
    INSERT INTO user_settings (user_id, key, value) SELECT ${defaultUserId}, key, value FROM settings;
    DROP TABLE IF EXISTS settings;
    
    PRAGMA foreign_keys=ON;
  `);
  console.log("Migration complete.");
}

// Authentication Middleware
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.status(403).json({ error: 'Forbidden' });
    req.user = user;
    next();
  });
};

// --- Auth Routes ---
app.post('/api/auth/register', (req, res) => {
  const { email, password, store_name } = req.body;
  try {
    const hash = bcrypt.hashSync(password, 10);
    const stmt = db.prepare('INSERT INTO users (email, password_hash, store_name) VALUES (?, ?, ?)');
    const info = stmt.run(email, hash, store_name);
    
    // Initialize default settings for new user
    const userId = info.lastInsertRowid;
    db.prepare('INSERT INTO user_settings (user_id, key, value) VALUES (?, ?, ?)').run(userId, 'low_stock_email', email);
    db.prepare('INSERT INTO user_settings (user_id, key, value) VALUES (?, ?, ?)').run(userId, 'low_stock_threshold', '5');
    db.prepare('INSERT INTO user_settings (user_id, key, value) VALUES (?, ?, ?)').run(userId, 'low_stock_alerts_enabled', 'true');

    const token = jwt.sign({ id: userId, email, store_name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: userId, email, store_name } });
  } catch (error: any) {
    if (error.message.includes('UNIQUE constraint failed')) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as any;
  
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id, email: user.email, store_name: user.store_name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, email: user.email, store_name: user.store_name } });
});

app.get('/api/auth/me', authenticateToken, (req: any, res) => {
  res.json({ user: req.user });
});

// API Routes (Protected)
app.use('/api', authenticateToken);

// --- Products ---
app.get('/api/products', (req: any, res) => {
  const products = db.prepare('SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  const variants = db.prepare('SELECT product_variants.* FROM product_variants JOIN products ON product_variants.product_id = products.id WHERE products.user_id = ?').all(req.user.id) as any[];
  
  const productsWithVariants = products.map((p: any) => ({
    ...p,
    variants: variants.filter(v => v.product_id === p.id)
  }));
  
  res.json(productsWithVariants);
});

app.post('/api/products', (req: any, res) => {
  const { name, description, sku, barcode, price, cost, stock, category, brand, weight, dimensions, image_url, variants } = req.body;
  
  const insertProduct = db.transaction(() => {
    let finalStock = stock;
    if (variants && variants.length > 0) {
      finalStock = variants.reduce((sum: number, v: any) => sum + (Number(v.stock) || 0), 0);
    }

    const stmt = db.prepare('INSERT INTO products (user_id, name, description, sku, barcode, price, cost, stock, category, brand, weight, dimensions, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    const info = stmt.run(req.user.id, name, description, sku, barcode, price, cost, finalStock, category, brand, weight, dimensions, image_url);
    const productId = info.lastInsertRowid;
    
    if (variants && variants.length > 0) {
      const variantStmt = db.prepare('INSERT INTO product_variants (product_id, name, sku, price, stock) VALUES (?, ?, ?, ?, ?)');
      for (const v of variants) {
        variantStmt.run(productId, v.name, v.sku, v.price, v.stock);
      }
    }
    return productId;
  });

  try {
    const id = insertProduct();
    res.json({ id, ...req.body });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

app.put('/api/products/:id', (req: any, res) => {
  const { name, description, sku, barcode, price, cost, stock, category, brand, weight, dimensions, image_url, variants } = req.body;
  const productId = req.params.id;
  
  const updateProduct = db.transaction(() => {
    let finalStock = stock;
    if (variants && variants.length > 0) {
      finalStock = variants.reduce((sum: number, v: any) => sum + (Number(v.stock) || 0), 0);
    }

    const stmt = db.prepare('UPDATE products SET name = ?, description = ?, sku = ?, barcode = ?, price = ?, cost = ?, stock = ?, category = ?, brand = ?, weight = ?, dimensions = ?, image_url = ? WHERE id = ? AND user_id = ?');
    const info = stmt.run(name, description, sku, barcode, price, cost, finalStock, category, brand, weight, dimensions, image_url, productId, req.user.id);
    
    if (info.changes === 0) throw new Error('Product not found or unauthorized');

    db.prepare('DELETE FROM product_variants WHERE product_id = ?').run(productId);
    
    if (variants && variants.length > 0) {
      const variantStmt = db.prepare('INSERT INTO product_variants (product_id, name, sku, price, stock) VALUES (?, ?, ?, ?, ?)');
      for (const v of variants) {
        variantStmt.run(productId, v.name, v.sku, v.price, v.stock);
      }
    }
  });

  try {
    updateProduct();
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

app.put('/api/inventory/stock', (req: any, res) => {
  const { items } = req.body; // Array of { id, isVariant, stock }
  const updateStock = db.transaction(() => {
    const updatedProductIds = new Set<number>();

    for (const item of items) {
      if (item.isVariant) {
        // Ensure variant belongs to user's product
        const variant = db.prepare('SELECT product_id FROM product_variants WHERE id = ?').get(item.id) as any;
        if (variant) {
          const product = db.prepare('SELECT id FROM products WHERE id = ? AND user_id = ?').get(variant.product_id, req.user.id);
          if (product) {
            db.prepare('UPDATE product_variants SET stock = ? WHERE id = ?').run(item.stock, item.id);
            updatedProductIds.add(variant.product_id);
          }
        }
      } else {
        db.prepare('UPDATE products SET stock = ? WHERE id = ? AND user_id = ?').run(item.stock, item.id, req.user.id);
      }
    }

    // Recalculate total stock for products whose variants were updated
    for (const productId of updatedProductIds) {
      const variants = db.prepare('SELECT stock FROM product_variants WHERE product_id = ?').all(productId) as any[];
      const totalStock = variants.reduce((sum, v) => sum + (Number(v.stock) || 0), 0);
      db.prepare('UPDATE products SET stock = ? WHERE id = ? AND user_id = ?').run(totalStock, productId, req.user.id);
    }
  });

  try {
    updateStock();
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

app.delete('/api/products/:id', (req: any, res) => {
  try {
    const info = db.prepare('DELETE FROM products WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
    if (info.changes === 0) return res.status(404).json({ error: 'Product not found or unauthorized' });
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

// --- Customers ---
app.get('/api/customers', (req: any, res) => {
  const customers = db.prepare('SELECT * FROM customers WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json(customers);
});

app.post('/api/customers', (req: any, res) => {
  const { name, email, phone, address, notes } = req.body;
  try {
    const stmt = db.prepare('INSERT INTO customers (user_id, name, email, phone, address, notes) VALUES (?, ?, ?, ?, ?, ?)');
    const info = stmt.run(req.user.id, name, email, phone, address, notes);
    res.json({ id: info.lastInsertRowid, ...req.body });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

// --- Orders ---
app.get('/api/orders', (req: any, res) => {
  const orders = db.prepare(`
    SELECT orders.*, customers.name as customer_name 
    FROM orders 
    LEFT JOIN customers ON orders.customer_id = customers.id 
    WHERE orders.user_id = ?
    ORDER BY orders.created_at DESC
  `).all(req.user.id);
  res.json(orders);
});

app.get('/api/orders/:id', (req: any, res) => {
  const order = db.prepare(`
    SELECT orders.*, customers.name as customer_name, customers.email as customer_email, customers.address as customer_address, customers.phone as customer_phone
    FROM orders 
    LEFT JOIN customers ON orders.customer_id = customers.id 
    WHERE orders.id = ? AND orders.user_id = ?
  `).get(req.params.id, req.user.id);

  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  const items = db.prepare(`
    SELECT order_items.*, products.name as product_name, products.sku as product_sku, product_variants.name as variant_name
    FROM order_items
    LEFT JOIN products ON order_items.product_id = products.id
    LEFT JOIN product_variants ON order_items.variant_id = product_variants.id
    WHERE order_items.order_id = ?
  `).all(req.params.id);

  res.json({ ...order, items });
});

app.post('/api/orders', (req: any, res) => {
  const { customer_id, status, total_amount, shipping_cost, courier, tracking_number, items } = req.body;
  
  const createOrder = db.transaction((orderData, orderItems) => {
    const stmt = db.prepare('INSERT INTO orders (user_id, customer_id, status, total_amount, shipping_cost, courier, tracking_number) VALUES (?, ?, ?, ?, ?, ?, ?)');
    const info = stmt.run(req.user.id, orderData.customer_id, orderData.status, orderData.total_amount, orderData.shipping_cost, orderData.courier, orderData.tracking_number);
    const orderId = info.lastInsertRowid;

    const itemStmt = db.prepare('INSERT INTO order_items (order_id, product_id, variant_id, quantity, price) VALUES (?, ?, ?, ?, ?)');
    const updateProductStockStmt = db.prepare('UPDATE products SET stock = stock - ? WHERE id = ? AND user_id = ?');
    const updateVariantStockStmt = db.prepare('UPDATE product_variants SET stock = stock - ? WHERE id = ?');

    for (const item of orderItems) {
      itemStmt.run(orderId, item.product_id, item.variant_id || null, item.quantity, item.price);
      
      if (item.variant_id) {
        updateVariantStockStmt.run(item.quantity, item.variant_id);
        // Recalculate parent product stock
        const variants = db.prepare('SELECT stock FROM product_variants WHERE product_id = ?').all(item.product_id) as any[];
        const totalStock = variants.reduce((sum, v) => sum + (Number(v.stock) || 0), 0);
        db.prepare('UPDATE products SET stock = ? WHERE id = ? AND user_id = ?').run(totalStock, item.product_id, req.user.id);
      } else {
        updateProductStockStmt.run(item.quantity, item.product_id, req.user.id);
      }
    }

    // Record Income
    const incomeStmt = db.prepare('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)');
    incomeStmt.run(req.user.id, 'Income', orderData.total_amount, `Order #${orderId}`);

    return orderId;
  });

  try {
    const orderId = createOrder({ customer_id, status, total_amount, shipping_cost, courier, tracking_number }, items);
    res.json({ id: orderId, success: true });
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

app.put('/api/orders/:id/status', (req: any, res) => {
  const { status } = req.body;
  const info = db.prepare('UPDATE orders SET status = ? WHERE id = ? AND user_id = ?').run(status, req.params.id, req.user.id);
  if (info.changes === 0) return res.status(404).json({ error: 'Order not found or unauthorized' });
  res.json({ success: true });
});

// --- Dashboard Analytics ---
app.get('/api/analytics', (req: any, res) => {
  const settingsObj = db.prepare('SELECT key, value FROM user_settings WHERE user_id = ?').all(req.user.id) as any[];
  const thresholdSetting = settingsObj.find((s: any) => s.key === 'low_stock_threshold');
  const threshold = thresholdSetting ? parseInt(thresholdSetting.value, 10) : 5;

  const totalRevenue = db.prepare('SELECT SUM(total_amount) as total FROM orders WHERE status != \'Cancelled\' AND user_id = ?').get(req.user.id) as {total: number};
  const totalOrders = db.prepare('SELECT COUNT(*) as count FROM orders WHERE user_id = ?').get(req.user.id) as {count: number};
  const lowStockProducts = db.prepare('SELECT COUNT(*) as count FROM products WHERE stock <= ? AND user_id = ?').get(threshold, req.user.id) as {count: number};
  const lowStockVariants = db.prepare('SELECT COUNT(*) as count FROM product_variants JOIN products ON product_variants.product_id = products.id WHERE product_variants.stock <= ? AND products.user_id = ?').get(threshold, req.user.id) as {count: number};
  const lowStock = lowStockProducts.count + lowStockVariants.count;
  const totalCustomers = db.prepare('SELECT COUNT(*) as count FROM customers WHERE user_id = ?').get(req.user.id) as {count: number};
  
  const recentSales = db.prepare(`
    SELECT date(created_at) as date, SUM(total_amount) as amount 
    FROM orders 
    WHERE status != 'Cancelled' AND user_id = ?
    GROUP BY date(created_at) 
    ORDER BY date(created_at) DESC 
    LIMIT 7
  `).all(req.user.id);

  res.json({
    totalRevenue: totalRevenue.total || 0,
    totalOrders: totalOrders.count || 0,
    lowStock: lowStock || 0,
    totalCustomers: totalCustomers.count || 0,
    recentSales: recentSales.reverse()
  });
});

// --- AI Tools ---
app.post('/api/ai/generate', async (req, res) => {
  const { prompt, type } = req.body;
  
  if (!process.env.GEMINI_API_KEY) {
    return res.status(500).json({ error: 'Gemini API key is missing' });
  }

  try {
    const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
    let systemInstruction = '';
    
    if (type === 'description') {
      systemInstruction = 'You are an expert e-commerce copywriter. Write a compelling, SEO-friendly product description based on the provided details. Keep it professional and engaging.';
    } else if (type === 'seo') {
      systemInstruction = 'You are an SEO expert. Generate an optimized SEO title and 5 comma-separated keywords for the following product. Format as: Title: [title]\\nKeywords: [keywords]';
    }

    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: prompt,
      config: {
        systemInstruction
      }
    });

    res.json({ result: response.text });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// --- Settings ---
app.get('/api/settings', (req: any, res) => {
  const settings = db.prepare('SELECT * FROM user_settings WHERE user_id = ?').all(req.user.id) as {key: string, value: string}[];
  const settingsObj = settings.reduce((acc, curr) => {
    acc[curr.key] = curr.value;
    return acc;
  }, {} as Record<string, string>);
  res.json(settingsObj);
});

app.post('/api/settings', (req: any, res) => {
  const settings = req.body;
  const stmt = db.prepare('INSERT OR REPLACE INTO user_settings (user_id, key, value) VALUES (?, ?, ?)');
  
  db.transaction(() => {
    for (const [key, value] of Object.entries(settings)) {
      stmt.run(req.user.id, key, String(value));
    }
  })();
  
  res.json({ success: true });
});

app.post('/api/notifications/test-low-stock', async (req: any, res) => {
  try {
    const settings = db.prepare('SELECT * FROM user_settings WHERE user_id = ?').all(req.user.id) as {key: string, value: string}[];
    const settingsObj = settings.reduce((acc, curr) => {
      acc[curr.key] = curr.value;
      return acc;
    }, {} as Record<string, string>);

    if (settingsObj.low_stock_alerts_enabled !== 'true') {
      return res.status(400).json({ error: 'Low stock alerts are disabled.' });
    }

    const threshold = parseInt(settingsObj.low_stock_threshold || '5', 10);
    const email = settingsObj.low_stock_email;

    if (!email) {
      return res.status(400).json({ error: 'No email address configured for alerts.' });
    }

    // Find low stock products
    const products = db.prepare('SELECT * FROM products WHERE user_id = ?').all(req.user.id) as any[];
    const variants = db.prepare('SELECT product_variants.* FROM product_variants JOIN products ON product_variants.product_id = products.id WHERE products.user_id = ?').all(req.user.id) as any[];
    
    const lowStockItems: any[] = [];
    
    for (const p of products) {
      const pVariants = variants.filter(v => v.product_id === p.id);
      if (pVariants.length > 0) {
        for (const v of pVariants) {
          if (v.stock <= threshold) {
            lowStockItems.push({ name: `${p.name} - ${v.name}`, stock: v.stock, sku: v.sku });
          }
        }
      } else {
        if (p.stock <= threshold) {
          lowStockItems.push({ name: p.name, stock: p.stock, sku: p.sku });
        }
      }
    }

    if (lowStockItems.length === 0) {
      return res.json({ success: true, message: 'No items are currently low on stock.', items: 0 });
    }

    // In a real app, you would use nodemailer or a service like SendGrid here.
    // For this demo, we'll simulate sending an email.
    console.log(`\n--- SIMULATED EMAIL ---`);
    console.log(`To: ${email}`);
    console.log(`Subject: Low Stock Alert - ${lowStockItems.length} items need attention`);
    console.log(`Body:`);
    console.log(`The following items are running low on stock (Threshold: ${threshold}):`);
    lowStockItems.forEach(item => {
      console.log(`- ${item.name} (SKU: ${item.sku || 'N/A'}): ${item.stock} remaining`);
    });
    console.log(`-----------------------\n`);

    res.json({ 
      success: true, 
      message: `Simulated email sent to ${email} with ${lowStockItems.length} low stock items.`,
      items: lowStockItems.length
    });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// Vite middleware for development
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
