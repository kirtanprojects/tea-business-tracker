import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import pkg from "pg";
import excelJS from "exceljs";
import PDFDocument from "pdfkit";
import fs from "fs";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv"; // ADD THIS

// Load environment variables
dotenv.config(); // ADD THIS

const { Pool } = pkg;
const app = express();

app.use(bodyParser.json());
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.static("."));

// JWT Configuration - USE ENVIRONMENT VARIABLE
const JWT_SECRET =
  process.env.JWT_SECRET ||
  "tea_business_tracker_secret_key_2025_change_in_production";
const JWT_EXPIRY = process.env.JWT_EXPIRY || "24h";

// ✅ PostgreSQL connection - USE ENVIRONMENT VARIABLE
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // UPDATE THIS
  ssl: {
    rejectUnauthorized: false, // IMPORTANT FOR NEON
  },
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error("❌ Error connecting to Neon database:", err.message);
  } else {
    console.log("✅ Successfully connected to Neon PostgreSQL database");
    release();
  }
});

// ========== DATABASE INITIALIZATION ==========

// ✅ Create users table
const createUsersTable = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(100) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE
      );
    `);
    console.log("✅ Users table created or already exists");

    // Check if default users exist
    const checkAdmin = await pool.query(
      "SELECT * FROM users WHERE username = 'admin'"
    );
    if (checkAdmin.rows.length === 0) {
      // Create default admin user (password: admin123)
      const hashedAdminPassword = await bcrypt.hash("admin123", 10);
      await pool.query(
        `INSERT INTO users (username, password_hash, full_name, role, is_active) 
         VALUES ($1, $2, $3, $4, $5)`,
        ["admin", hashedAdminPassword, "Administrator", "admin", true]
      );
      console.log(
        "✅ Default admin user created (username: admin, password: admin123)"
      );
    }

    const checkUser = await pool.query(
      "SELECT * FROM users WHERE username = 'user'"
    );
    if (checkUser.rows.length === 0) {
      // Create default regular user (password: user123)
      const hashedUserPassword = await bcrypt.hash("user123", 10);
      await pool.query(
        `INSERT INTO users (username, password_hash, full_name, role, is_active) 
         VALUES ($1, $2, $3, $4, $5)`,
        ["user", hashedUserPassword, "Regular User", "user", true]
      );
      console.log(
        "✅ Default user created (username: user, password: user123)"
      );
    }
  } catch (err) {
    console.error("❌ Error creating users table:", err);
  }
};

// ✅ Create sequences
const createSequences = async () => {
  try {
    await pool.query(`
      CREATE SEQUENCE IF NOT EXISTS purchase_seq START 1;
      CREATE SEQUENCE IF NOT EXISTS sales_seq START 1;
    `);
    console.log("✅ Sequences created or already exist");
  } catch (err) {
    console.error("❌ Error creating sequences:", err);
  }
};

// ✅ Create purchase table if not exists (UPDATED)
const createPurchaseTable = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS purchase_records (
        id SERIAL PRIMARY KEY,
        purchase_id VARCHAR(15) UNIQUE NOT NULL DEFAULT 'P' || TO_CHAR(CURRENT_DATE, 'YYMMDD') || LPAD(NEXTVAL('purchase_seq')::VARCHAR, 4, '0'),
        garden_name VARCHAR(100) NOT NULL,
        num_bags INTEGER NOT NULL DEFAULT 0,
        weight_kg DECIMAL(10,2) NOT NULL DEFAULT 0,
        total_price DECIMAL(10,2) NOT NULL,
        price_per_kg DECIMAL(10,2) NOT NULL DEFAULT 0,
        total_amount DECIMAL(10,2) NOT NULL,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Purchase table created or already exists");
  } catch (err) {
    console.error("❌ Error creating purchase table:", err);
  }
};

// ✅ Create sales table if not exists (UPDATED)
const createSalesTable = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS sales_records (
        id SERIAL PRIMARY KEY,
        sales_id VARCHAR(15) UNIQUE NOT NULL DEFAULT 'S' || TO_CHAR(CURRENT_DATE, 'YYMMDD') || LPAD(NEXTVAL('sales_seq')::VARCHAR, 4, '0'),
        customer_name VARCHAR(100) NOT NULL,
        sale_type VARCHAR(20) NOT NULL DEFAULT 'retail',
        tea_type VARCHAR(20) NOT NULL,
        details JSONB NOT NULL,
        total_amount DECIMAL(10,2) NOT NULL,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Sales table created or already exists");
  } catch (err) {
    console.error("❌ Error creating sales table:", err);
  }
};

// ✅ Create packaging table if not exists
const createPackagingTable = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS packaging_records (
        id SERIAL PRIMARY KEY,
        product VARCHAR(50),
        packaging_size VARCHAR(20),
        packets_made NUMERIC,
        remaining_stock NUMERIC,
        cost_per_packet NUMERIC,
        sell_per_packet NUMERIC,
        profit_per_packet NUMERIC,
        total_profit NUMERIC,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Packaging table created or already exists");
  } catch (err) {
    console.error("❌ Error creating packaging table:", err);
  }
};

// Initialize all tables
const initializeDatabase = async () => {
  try {
    console.log("🔄 Initializing database...");
    await createUsersTable();
    await createSequences();
    await createPurchaseTable();
    await createSalesTable();
    await createPackagingTable();
    console.log("✅ Database initialization completed");
  } catch (err) {
    console.error("❌ Database initialization failed:", err);
  }
};

// Run database initialization
initializeDatabase();

// ========== AUTHENTICATION MIDDLEWARE ==========

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Access token required",
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: "Invalid or expired token",
      });
    }
    req.user = user;
    next();
  });
};

const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: "Insufficient permissions",
      });
    }

    next();
  };
};

// ========== AUTHENTICATION ROUTES ==========

// ✅ User Login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required",
      });
    }

    // Find user
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1 AND is_active = TRUE",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
      });
    }

    const user = result.rows[0];

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
      });
    }

    // Update last login
    await pool.query(
      "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1",
      [user.id]
    );

    // Create JWT token
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: user.role,
        full_name: user.full_name,
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({
      success: false,
      message: "Server error during login",
    });
  }
});

// ✅ Verify Token
app.get("/api/verify-token", authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: req.user,
  });
});

// ✅ Logout (client-side only, but provides endpoint for consistency)
app.post("/api/logout", authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: "Logged out successfully",
  });
});

// ✅ Get current user profile
app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, full_name, role, created_at, last_login 
       FROM users WHERE id = $1 AND is_active = TRUE`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.json({
      success: true,
      user: result.rows[0],
    });
  } catch (err) {
    console.error("❌ Profile fetch error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// ✅ Update user profile
app.put("/api/profile", authenticateToken, async (req, res) => {
  try {
    const { full_name } = req.body;

    if (!full_name) {
      return res.status(400).json({
        success: false,
        message: "Full name is required",
      });
    }

    const result = await pool.query(
      `UPDATE users SET full_name = $1 
       WHERE id = $2 AND is_active = TRUE 
       RETURNING id, username, full_name, role`,
      [full_name, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.json({
      success: true,
      message: "Profile updated successfully",
      user: result.rows[0],
    });
  } catch (err) {
    console.error("❌ Profile update error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// ✅ Change password
app.post("/api/change-password", authenticateToken, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;

    if (!current_password || !new_password) {
      return res.status(400).json({
        success: false,
        message: "Both current and new password are required",
      });
    }

    // Get current password hash
    const userResult = await pool.query(
      "SELECT password_hash FROM users WHERE id = $1 AND is_active = TRUE",
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Verify current password
    const validPassword = await bcrypt.compare(
      current_password,
      userResult.rows[0].password_hash
    );
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(new_password, 10);

    // Update password
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [
      hashedPassword,
      req.user.id,
    ]);

    res.json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (err) {
    console.error("❌ Password change error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// ✅ Get user-specific statistics
app.get("/api/user/stats", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // User's purchase stats
    const purchaseRes = await pool.query(
      `SELECT 
        COALESCE(SUM(weight_kg), 0) as user_total_weight,
        COALESCE(SUM(total_amount), 0) as user_total_investment,
        COUNT(*) as user_purchase_count
       FROM purchase_records 
       WHERE created_by = $1`,
      [userId]
    );

    // User's sales stats
    const salesRes = await pool.query(
      `SELECT 
        COALESCE(SUM((details->>'weight_kg')::DECIMAL), 0) as user_sold_weight,
        COALESCE(SUM(total_amount), 0) as user_sales_revenue,
        COUNT(*) as user_sales_count
       FROM sales_records 
       WHERE created_by = $1`,
      [userId]
    );

    const userStats = {
      purchase_count: parseInt(purchaseRes.rows[0].user_purchase_count) || 0,
      purchase_weight: parseFloat(
        purchaseRes.rows[0].user_total_weight
      ).toFixed(2),
      purchase_investment: parseFloat(
        purchaseRes.rows[0].user_total_investment
      ).toFixed(2),
      sales_count: parseInt(salesRes.rows[0].user_sales_count) || 0,
      sales_weight: parseFloat(salesRes.rows[0].user_sold_weight).toFixed(2),
      sales_revenue: parseFloat(salesRes.rows[0].user_sales_revenue).toFixed(2),
    };

    res.json({
      success: true,
      stats: userStats,
    });
  } catch (err) {
    console.error("❌ Error fetching user stats:", err);
    res.status(500).json({
      success: false,
      message: "Database fetch error",
    });
  }
});

// ========== USER STATS ROUTES ==========

// ✅ Get user purchase count
app.get("/api/user/purchase-count", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT COUNT(*) FROM purchase_records WHERE created_by = $1",
      [req.user.id]
    );

    res.json({
      success: true,
      count: parseInt(result.rows[0].count) || 0,
    });
  } catch (err) {
    console.error("❌ Purchase count error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// ✅ Get user sales count
app.get("/api/user/sales-count", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT COUNT(*) FROM sales_records WHERE created_by = $1",
      [req.user.id]
    );

    res.json({
      success: true,
      count: parseInt(result.rows[0].count) || 0,
    });
  } catch (err) {
    console.error("❌ Sales count error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// ========== ADMIN ROUTES ==========

// ✅ Get ALL purchase history (admin only)
app.get(
  "/api/admin/purchase-history",
  authenticateToken,
  authorizeRole(["admin"]),
  async (req, res) => {
    try {
      const query = `
      SELECT pr.*, u.username as created_by_username 
      FROM purchase_records pr
      LEFT JOIN users u ON pr.created_by = u.id
      ORDER BY pr.created_at DESC
    `;
      const result = await pool.query(query);
      res.json(result.rows);
    } catch (err) {
      console.error("❌ Error fetching admin purchase history:", err);
      res.status(500).json({
        success: false,
        message: "Database fetch error",
      });
    }
  }
);

// ✅ Get ALL sales history (admin only)
app.get(
  "/api/admin/sales-history",
  authenticateToken,
  authorizeRole(["admin"]),
  async (req, res) => {
    try {
      const query = `
      SELECT sr.*, u.username as created_by_username 
      FROM sales_records sr
      LEFT JOIN users u ON sr.created_by = u.id
      ORDER BY sr.created_at DESC
    `;
      const result = await pool.query(query);
      res.json(result.rows);
    } catch (err) {
      console.error("❌ Error fetching admin sales history:", err);
      res.status(500).json({
        success: false,
        message: "Database fetch error",
      });
    }
  }
);

// ✅ Get all users (admin only)
app.get(
  "/api/admin/users",
  authenticateToken,
  authorizeRole(["admin"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, username, full_name, role, created_at, last_login, is_active 
       FROM users ORDER BY created_at DESC`
      );
      res.json({
        success: true,
        users: result.rows,
      });
    } catch (err) {
      console.error("❌ Users fetch error:", err);
      res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }
);

// ✅ Create new user (admin only)
app.post(
  "/api/admin/users",
  authenticateToken,
  authorizeRole(["admin"]),
  async (req, res) => {
    try {
      const { username, password, full_name, role } = req.body;

      if (!username || !password || !full_name) {
        return res.status(400).json({
          success: false,
          message: "Username, password, and full name are required",
        });
      }

      // Validate role
      const validRoles = ["admin", "user"];
      const userRole = validRoles.includes(role) ? role : "user";

      // Check if username exists
      const checkUser = await pool.query(
        "SELECT id FROM users WHERE username = $1",
        [username]
      );

      if (checkUser.rows.length > 0) {
        return res.status(400).json({
          success: false,
          message: "Username already exists",
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      const result = await pool.query(
        `INSERT INTO users (username, password_hash, full_name, role, is_active) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, username, full_name, role, created_at`,
        [username, hashedPassword, full_name, userRole, true]
      );

      res.json({
        success: true,
        message: "User created successfully",
        user: result.rows[0],
      });
    } catch (err) {
      console.error("❌ User creation error:", err);
      res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }
);

// ✅ Update user (admin only)
app.put(
  "/api/admin/users/:id",
  authenticateToken,
  authorizeRole(["admin"]),
  async (req, res) => {
    try {
      const { username, full_name, role, is_active } = req.body;
      const userId = parseInt(req.params.id);

      if (!userId || isNaN(userId)) {
        return res.status(400).json({
          success: false,
          message: "Valid user ID is required",
        });
      }

      // Prevent modifying own account's role or active status
      if (userId === req.user.id) {
        if (role !== req.user.role) {
          return res.status(400).json({
            success: false,
            message: "Cannot change your own role",
          });
        }
        if (is_active === false) {
          return res.status(400).json({
            success: false,
            message: "Cannot deactivate your own account",
          });
        }
      }

      const result = await pool.query(
        `UPDATE users 
       SET username = COALESCE($1, username), 
           full_name = COALESCE($2, full_name), 
           role = COALESCE($3, role),
           is_active = COALESCE($4, is_active)
       WHERE id = $5 
       RETURNING id, username, full_name, role, created_at, is_active`,
        [username, full_name, role, is_active, userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      res.json({
        success: true,
        message: "User updated successfully",
        user: result.rows[0],
      });
    } catch (err) {
      console.error("❌ User update error:", err);
      res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }
);

// ✅ Delete user (admin only)
app.delete(
  "/api/admin/users/:id",
  authenticateToken,
  authorizeRole(["admin"]),
  async (req, res) => {
    try {
      const userId = parseInt(req.params.id);

      if (!userId || isNaN(userId)) {
        return res.status(400).json({
          success: false,
          message: "Valid user ID is required",
        });
      }

      // Prevent deleting yourself
      if (userId === req.user.id) {
        return res.status(400).json({
          success: false,
          message: "Cannot delete your own account",
        });
      }

      // Soft delete (set is_active to false)
      const result = await pool.query(
        "UPDATE users SET is_active = FALSE WHERE id = $1 RETURNING id",
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      res.json({
        success: true,
        message: "User deactivated successfully",
      });
    } catch (err) {
      console.error("❌ User delete error:", err);
      res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }
);

// ✅ Reset user password (admin only)
app.post(
  "/api/admin/users/:id/reset-password",
  authenticateToken,
  authorizeRole(["admin"]),
  async (req, res) => {
    try {
      const { new_password } = req.body;
      const userId = parseInt(req.params.id);

      if (!new_password) {
        return res.status(400).json({
          success: false,
          message: "New password is required",
        });
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(new_password, 10);

      const result = await pool.query(
        "UPDATE users SET password_hash = $1 WHERE id = $2 RETURNING id",
        [hashedPassword, userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      res.json({
        success: true,
        message: "Password reset successfully",
      });
    } catch (err) {
      console.error("❌ Password reset error:", err);
      res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }
);

// ✅ Get available stock for weight field (protected) - COMPANY STOCK FOR ALL USERS
app.get("/api/available-stock", authenticateToken, async (req, res) => {
  try {
    console.log(
      `📦 Fetching available stock for weight field - User: ${req.user.username}`
    );

    // Company stock = ALL purchases - ALL sales
    const purchaseQuery = `
      SELECT COALESCE(SUM(weight_kg), 0) as total_weight 
      FROM purchase_records
    `;

    const salesQuery = `
      SELECT COALESCE(SUM((details->>'weight_kg')::DECIMAL), 0) as sold_weight 
      FROM sales_records
    `;

    const purchaseResult = await pool.query(purchaseQuery);
    const salesResult = await pool.query(salesQuery);

    const totalPurchasedWeight =
      parseFloat(purchaseResult.rows[0].total_weight) || 0;
    const totalSoldWeight = parseFloat(salesResult.rows[0].sold_weight) || 0;
    const remainingWeight = Math.max(0, totalPurchasedWeight - totalSoldWeight);

    console.log(`📦 Available stock: ${remainingWeight.toFixed(2)} kg`);

    res.json({
      success: true,
      available_stock: remainingWeight,
      available_stock_formatted: remainingWeight.toFixed(2) + " kg",
      message: `Available stock: ${remainingWeight.toFixed(2)} kg`,
    });
  } catch (err) {
    console.error("❌ Error fetching available stock:", err);
    res.status(500).json({
      success: false,
      message: "Database fetch error",
    });
  }
});

// ========== PROTECTED BUSINESS ROUTES ==========

// ✅ Save purchase record (protected) - ALL USERS CAN SAVE
app.post("/api/save-purchase", authenticateToken, async (req, res) => {
  try {
    const {
      garden_name,
      num_bags,
      weight_kg,
      total_price,
      price_per_kg,
      total_amount,
    } = req.body;

    // Improved validation
    if (!garden_name || garden_name.trim() === "") {
      return res.status(400).json({
        success: false,
        message: "Garden name is required",
      });
    }

    if (!total_price || isNaN(total_price) || total_price <= 0) {
      return res.status(400).json({
        success: false,
        message: "Valid total price is required",
      });
    }

    // Ensure we have at least bags or weight
    const bags = parseInt(num_bags) || 0;
    const weight = parseFloat(weight_kg) || 0;

    if (bags <= 0 && weight <= 0) {
      return res.status(400).json({
        success: false,
        message: "Please enter either number of bags or weight in kg",
      });
    }

    // Calculate price_per_kg if not provided but weight is available
    let finalPricePerKg = parseFloat(price_per_kg) || 0;
    if (finalPricePerKg <= 0 && weight > 0) {
      finalPricePerKg = total_price / weight;
    }

    const result = await pool.query(
      `INSERT INTO purchase_records 
      (garden_name, num_bags, weight_kg, total_price, price_per_kg, total_amount, created_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING purchase_id, created_at`,
      [
        garden_name.trim(),
        bags,
        weight,
        parseFloat(total_price),
        finalPricePerKg,
        parseFloat(total_amount || total_price),
        req.user.id,
      ]
    );

    res.json({
      success: true,
      message: "✅ Purchase record saved successfully!",
      purchase_id: result.rows[0].purchase_id,
      created_at: result.rows[0].created_at,
    });
  } catch (err) {
    console.error("❌ Database Error:", err);
    res.status(500).json({
      success: false,
      message: "Database error: " + err.message,
    });
  }
});

// ✅ Get user-specific purchase history (regular users see only their own)
app.get("/api/user/purchase-history", authenticateToken, async (req, res) => {
  try {
    if (req.user.role === "admin") {
      // Admin sees all
      const query = `
        SELECT pr.*, u.username as created_by_username 
        FROM purchase_records pr
        LEFT JOIN users u ON pr.created_by = u.id
        ORDER BY pr.created_at DESC
      `;
      const result = await pool.query(query);
      res.json(result.rows);
    } else {
      // Regular user sees only their own
      const query = `
        SELECT pr.*, u.username as created_by_username 
        FROM purchase_records pr
        LEFT JOIN users u ON pr.created_by = u.id
        WHERE pr.created_by = $1
        ORDER BY pr.created_at DESC
      `;
      const result = await pool.query(query, [req.user.id]);
      res.json(result.rows);
    }
  } catch (err) {
    console.error("❌ Error fetching purchase history:", err);
    res.status(500).json({
      success: false,
      message: "Database fetch error",
    });
  }
});

// ✅ Save sale record (protected) - ALL USERS CAN SAVE
app.post("/api/save-sale", authenticateToken, async (req, res) => {
  try {
    const {
      customer_name,
      sale_type = "retail",
      tea_type,
      details,
      total_amount,
    } = req.body;

    // Improved validation
    if (!customer_name || customer_name.trim() === "") {
      return res.status(400).json({
        success: false,
        message: "Customer name is required",
      });
    }

    if (!tea_type || tea_type.trim() === "") {
      return res.status(400).json({
        success: false,
        message: "Tea type is required",
      });
    }

    if (!total_amount || isNaN(total_amount) || total_amount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Valid total amount is required",
      });
    }

    // Validate details object
    if (!details || typeof details !== "object") {
      return res.status(400).json({
        success: false,
        message: "Valid details are required",
      });
    }

    // Ensure weight_kg is present in details
    if (!details.weight_kg || details.weight_kg <= 0) {
      return res.status(400).json({
        success: false,
        message: "Valid weight is required in details",
      });
    }

    const result = await pool.query(
      `INSERT INTO sales_records 
      (customer_name, sale_type, tea_type, details, total_amount, created_by)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING sales_id, created_at`,
      [
        customer_name.trim(),
        sale_type,
        tea_type,
        details,
        parseFloat(total_amount),
        req.user.id,
      ]
    );

    res.json({
      success: true,
      message: "✅ Sale record saved successfully!",
      sales_id: result.rows[0].sales_id,
      created_at: result.rows[0].created_at,
    });
  } catch (err) {
    console.error("❌ Database Error:", err);
    res.status(500).json({
      success: false,
      message: "Database error: " + err.message,
    });
  }
});

// ✅ Get user-specific sales history (regular users see only their own)
app.get("/api/user/sales-history", authenticateToken, async (req, res) => {
  try {
    if (req.user.role === "admin") {
      // Admin sees all
      const query = `
        SELECT sr.*, u.username as created_by_username 
        FROM sales_records sr
        LEFT JOIN users u ON sr.created_by = u.id
        ORDER BY sr.created_at DESC
      `;
      const result = await pool.query(query);
      res.json(result.rows);
    } else {
      // Regular user sees only their own
      const query = `
        SELECT sr.*, u.username as created_by_username 
        FROM sales_records sr
        LEFT JOIN users u ON sr.created_by = u.id
        WHERE sr.created_by = $1
        ORDER BY sr.created_at DESC
      `;
      const result = await pool.query(query, [req.user.id]);
      res.json(result.rows);
    }
  } catch (err) {
    console.error("❌ Error fetching sales history:", err);
    res.status(500).json({
      success: false,
      message: "Database fetch error",
    });
  }
});

// ✅ Get purchase summary (protected) - COMPANY DATA FOR ALL
app.get("/api/purchase-summary", authenticateToken, async (req, res) => {
  try {
    // Company purchase summary (all users)
    const query = `
      SELECT 
        COALESCE(SUM(num_bags), 0) as total_bags,
        COALESCE(SUM(weight_kg), 0) as total_weight,
        COALESCE(SUM(total_amount), 0) as total_investment,
        COUNT(*) as total_purchases
      FROM purchase_records
    `;

    const result = await pool.query(query);
    const summary = result.rows[0];
    summary.total_weight = parseFloat(summary.total_weight).toFixed(2);
    summary.total_investment = parseFloat(summary.total_investment).toFixed(2);

    res.json(summary);
  } catch (err) {
    console.error("❌ Error fetching purchase summary:", err);
    res.status(500).json({
      success: false,
      message: "Database fetch error",
    });
  }
});

// ✅ Get sales summary (protected) - COMPANY DATA FOR ALL
app.get("/api/sales-summary", authenticateToken, async (req, res) => {
  try {
    // Company sales summary (all users)
    const query = `
      SELECT 
        COUNT(*) as total_sales,
        COALESCE(SUM(total_amount), 0) as total_revenue,
        COALESCE(SUM((details->>'weight_kg')::DECIMAL), 0) as total_weight_sold
      FROM sales_records
    `;

    const result = await pool.query(query);
    const summary = result.rows[0];
    summary.total_revenue = parseFloat(summary.total_revenue).toFixed(2);
    summary.total_weight_sold = parseFloat(summary.total_weight_sold).toFixed(
      2
    );

    res.json(summary);
  } catch (err) {
    console.error("❌ Error fetching sales summary:", err);
    res.status(500).json({
      success: false,
      message: "Database fetch error",
    });
  }
});

// ✅ Get current stock (WEIGHT-ONLY - protected) - FOR ALL USERS
app.get("/api/current-stock", authenticateToken, async (req, res) => {
  try {
    console.log(
      `📊 Fetching stock for user: ${req.user.username} (${req.user.role})`
    );

    // For ALL users, show company-wide stock
    const purchaseQuery = `
      SELECT 
        COALESCE(SUM(weight_kg), 0) as total_weight,
        COALESCE(SUM(total_amount), 0) as total_investment,
        COUNT(*) as total_purchases
      FROM purchase_records
    `;

    const salesQuery = `
      SELECT 
        COALESCE(SUM((details->>'weight_kg')::DECIMAL), 0) as sold_weight,
        COALESCE(SUM(total_amount), 0) as sales_revenue,
        COUNT(*) as total_sales
      FROM sales_records
    `;

    const purchaseResult = await pool.query(purchaseQuery);
    const salesResult = await pool.query(salesQuery);

    const totalPurchased = purchaseResult.rows[0];
    const totalSold = salesResult.rows[0];

    const totalPurchasedWeight = parseFloat(totalPurchased.total_weight) || 0;
    const totalSoldWeight = parseFloat(totalSold.sold_weight) || 0;
    const remainingWeight = Math.max(0, totalPurchasedWeight - totalSoldWeight);

    const totalInvestment = parseFloat(totalPurchased.total_investment) || 0;
    const salesRevenue = parseFloat(totalSold.sales_revenue) || 0;
    const profit = salesRevenue - totalInvestment;

    const stock = {
      total_weight: totalPurchasedWeight.toFixed(2),
      total_investment: totalInvestment.toFixed(2),
      sold_weight: totalSoldWeight.toFixed(2),
      sales_revenue: salesRevenue.toFixed(2),
      remaining_weight: remainingWeight.toFixed(2),
      profit: profit.toFixed(2),
      total_purchases: parseInt(totalPurchased.total_purchases) || 0,
      total_sales: parseInt(totalSold.total_sales) || 0,
      message: "Company Stock Information",
    };

    res.json(stock);
  } catch (err) {
    console.error("❌ Error fetching stock:", err);
    res.status(500).json({
      success: false,
      message: "Database fetch error",
    });
  }
});

// ✅ Stream Excel file instead of saving to disk (for Netlify compatibility)
app.get(
  "/api/download/purchase-excel",
  authenticateToken,
  authorizeRole(["admin"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT pr.*, u.username as created_by 
      FROM purchase_records pr
      LEFT JOIN users u ON pr.created_by = u.id
      ORDER BY pr.created_at DESC`
      );

      const workbook = new excelJS.Workbook();
      const worksheet = workbook.addWorksheet("Purchase Records");

      worksheet.columns = [
        { header: "Purchase ID", key: "purchase_id", width: 15 },
        { header: "Garden Name", key: "garden_name", width: 20 },
        { header: "Bags", key: "num_bags", width: 10 },
        { header: "Weight (kg)", key: "weight_kg", width: 15 },
        { header: "Total Price (₹)", key: "total_price", width: 15 },
        { header: "Price/kg (₹)", key: "price_per_kg", width: 15 },
        { header: "Total Amount (₹)", key: "total_amount", width: 15 },
        { header: "Created By", key: "created_by", width: 15 },
        { header: "Created At", key: "created_at", width: 20 },
      ];

      worksheet.addRows(
        result.rows.map((row) => ({
          purchase_id: row.purchase_id,
          garden_name: row.garden_name,
          num_bags: row.num_bags,
          weight_kg: parseFloat(row.weight_kg).toFixed(2),
          total_price: parseFloat(row.total_price).toFixed(2),
          price_per_kg: parseFloat(row.price_per_kg).toFixed(2),
          total_amount: parseFloat(row.total_amount).toFixed(2),
          created_by: row.created_by,
          created_at: new Date(row.created_at).toLocaleString("en-IN"),
        }))
      );

      // Add summary row
      const summaryResult = await pool.query(`
      SELECT 
        COALESCE(SUM(num_bags), 0) as total_bags,
        COALESCE(SUM(weight_kg), 0) as total_weight,
        COALESCE(SUM(total_amount), 0) as total_investment
      FROM purchase_records
    `);

      const summary = summaryResult.rows[0];

      worksheet.addRow([]);
      worksheet.addRow({
        purchase_id: "SUMMARY",
        garden_name: "TOTAL",
        num_bags: summary.total_bags,
        weight_kg: parseFloat(summary.total_weight).toFixed(2),
        total_amount: `₹${parseFloat(summary.total_investment).toFixed(2)}`,
      });

      // Set headers for file download
      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      );
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="purchase_history_${
          new Date().toISOString().split("T")[0]
        }.xlsx"`
      );

      // Stream the Excel file directly
      await workbook.xlsx.write(res);
      res.end();
    } catch (err) {
      console.error("❌ Purchase Excel Export Error:", err);
      res.status(500).json({
        success: false,
        message: "Error generating Excel file",
      });
    }
  }
);

// ✅ Stream Sales Excel file (for Netlify compatibility)
app.get(
  "/api/download/sales-excel",
  authenticateToken,
  authorizeRole(["admin"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT sr.*, u.username as created_by 
      FROM sales_records sr
      LEFT JOIN users u ON sr.created_by = u.id
      ORDER BY sr.created_at DESC`
      );

      const workbook = new excelJS.Workbook();
      const worksheet = workbook.addWorksheet("Sales Records");

      worksheet.columns = [
        { header: "Sales ID", key: "sales_id", width: 15 },
        { header: "Customer Name", key: "customer_name", width: 20 },
        { header: "Sale Type", key: "sale_type", width: 15 },
        { header: "Tea Type", key: "tea_type", width: 15 },
        { header: "Weight (kg)", key: "weight_kg", width: 15 },
        { header: "Total Amount (₹)", key: "total_amount", width: 15 },
        { header: "Created By", key: "created_by", width: 15 },
        { header: "Created At", key: "created_at", width: 20 },
      ];

      worksheet.addRows(
        result.rows.map((row) => ({
          sales_id: row.sales_id,
          customer_name: row.customer_name,
          sale_type: row.sale_type,
          tea_type: row.tea_type,
          weight_kg: parseFloat(row.details.weight_kg || 0).toFixed(2),
          total_amount: parseFloat(row.total_amount).toFixed(2),
          created_by: row.created_by,
          created_at: new Date(row.created_at).toLocaleString("en-IN"),
        }))
      );

      // Add summary row
      const summaryResult = await pool.query(`
      SELECT 
        COUNT(*) as total_sales,
        COALESCE(SUM(total_amount), 0) as total_revenue,
        COALESCE(SUM((details->>'weight_kg')::DECIMAL), 0) as total_weight_sold
      FROM sales_records
    `);

      const summary = summaryResult.rows[0];

      worksheet.addRow([]);
      worksheet.addRow({
        sales_id: "SUMMARY",
        customer_name: "TOTAL",
        weight_kg: parseFloat(summary.total_weight_sold).toFixed(2),
        total_amount: `₹${parseFloat(summary.total_revenue).toFixed(2)}`,
      });

      // Set headers for file download
      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      );
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="sales_history_${
          new Date().toISOString().split("T")[0]
        }.xlsx"`
      );

      // Stream the Excel file directly
      await workbook.xlsx.write(res);
      res.end();
    } catch (err) {
      console.error("❌ Sales Excel Export Error:", err);
      res.status(500).json({
        success: false,
        message: "Error generating Excel file",
      });
    }
  }
);

// ✅ Save packaging record (protected)
app.post("/api/save-packaging", authenticateToken, async (req, res) => {
  try {
    const {
      product,
      packaging_size,
      packets_made,
      remaining_stock,
      cost_per_packet,
      sell_per_packet,
      profit_per_packet,
      total_profit,
    } = req.body;

    await pool.query(
      `INSERT INTO packaging_records 
      (product, packaging_size, packets_made, remaining_stock, cost_per_packet, sell_per_packet, profit_per_packet, total_profit, created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        product,
        packaging_size,
        packets_made,
        remaining_stock,
        cost_per_packet,
        sell_per_packet,
        profit_per_packet,
        total_profit,
        req.user.id,
      ]
    );

    res.json({
      success: true,
      message: "✅ Record saved to database!",
    });
  } catch (err) {
    console.error("❌ Database Error:", err);
    res.status(500).json({
      success: false,
      message: "Database error",
    });
  }
});

// ✅ Fetch packaging history (protected)
app.get("/api/history", authenticateToken, async (req, res) => {
  try {
    let query = `
      SELECT pr.*, u.username as created_by_username 
      FROM packaging_records pr
      LEFT JOIN users u ON pr.created_by = u.id
      ORDER BY pr.created_at DESC
    `;

    let params = [];

    if (req.user.role !== "admin") {
      query = `
        SELECT pr.*, u.username as created_by_username 
        FROM packaging_records pr
        LEFT JOIN users u ON pr.created_by = u.id
        WHERE pr.created_by = $1
        ORDER BY pr.created_at DESC
      `;
      params = [req.user.id];
    }

    const result = await pool.query(query, params);

    // Format the response
    const formattedData = result.rows.map((row) => ({
      ...row,
      date: new Date(row.created_at).toISOString().split("T")[0],
      time: new Date(row.created_at).toTimeString().split(" ")[0],
    }));

    res.json(formattedData);
  } catch (err) {
    console.error("❌ Error fetching history:", err);
    res.status(500).json({
      success: false,
      message: "Database fetch error",
    });
  }
});

// ========== PUBLIC HEALTH CHECK ==========

// ✅ Health check endpoint (public)
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      status: "✅ Server is running",
      database: "Connected",
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || "development",
      authentication: "JWT-based authentication enabled",
      default_users: "admin/admin123, user/user123",
      deployment: "Netlify with Neon PostgreSQL",
    });
  } catch (err) {
    res.status(500).json({
      status: "❌ Database connection failed",
      error: err.message,
      environment: process.env.NODE_ENV || "development",
    });
  }
});

// ✅ Root endpoint
app.get("/", (req, res) => {
  res.json({
    message: "🍃 Tea Business Tracker API",
    status: "Running",
    version: "1.0.0",
    endpoints: {
      auth: "/api/login, /api/verify-token",
      user: "/api/user/*",
      admin: "/api/admin/*",
      business: "/api/save-purchase, /api/save-sale",
      health: "/api/health",
    },
  });
});

// Handle favicon.ico request to avoid 404
app.get("/favicon.ico", (req, res) => {
  res.status(204).end();
});

// 404 handler for undefined routes
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.method} ${req.url} not found`,
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("❌ Server error:", err);
  res.status(500).json({
    success: false,
    message: "Internal server error",
    error: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

// Start server with dynamic port for Netlify
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 Server running at: http://localhost:" + PORT);
  console.log("🔐 Authentication System Active");
  console.log("📊 Default Credentials:");
  console.log("   Admin: username='admin', password='admin123'");
  console.log("   User:  username='user',  password='user123'");
  console.log("🌐 Environment:", process.env.NODE_ENV || "development");
  console.log("📁 API Endpoints:");
  console.log("   POST /api/login");
  console.log("   GET  /api/verify-token");
  console.log("   GET  /api/profile");
  console.log("   POST /api/logout");
  console.log("   GET  /api/current-stock (COMPANY STOCK - All Users)");
  console.log("   GET  /api/purchase-history (All Users)");
  console.log("   GET  /api/sales-history (All Users)");
  console.log("   Excel Downloads: Admin Only");
  console.log(
    "   Protected routes require Authorization: Bearer <token> header"
  );
});

// Export for Netlify Functions
export default app;
