// backend/init-database-fixed.js
import mysql from 'mysql2';

const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'inventory_system',
    port: process.env.DB_PORT || 3306
};

function initializeDatabase() {
    return new Promise((resolve, reject) => {
        console.log('🔄 Inicializando base de datos...');

        // Crear conexión regular (no promise)
        const connection = mysql.createConnection({
            host: dbConfig.host,
            user: dbConfig.user,
            password: dbConfig.password,
            port: dbConfig.port,
            multipleStatements: true // Permitir múltiples sentencias
        });

        connection.connect(async (err) => {
            if (err) {
                console.error('❌ Error conectando a MySQL:', err.message);
                reject(err);
                return;
            }

            try {
                console.log('✅ Conectado a MySQL');

                // Crear base de datos si no existe
                await new Promise((resolve, reject) => {
                    connection.query('CREATE DATABASE IF NOT EXISTS inventory_system', (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
                console.log('✅ Base de datos inventory_system lista');

                // Usar la base de datos
                await new Promise((resolve, reject) => {
                    connection.query('USE inventory_system', (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });

                // Crear todas las tablas
                const tables = [
                    // Tabla companies
                    `CREATE TABLE IF NOT EXISTS companies (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        name VARCHAR(255) NOT NULL UNIQUE,
                        user_limit INT DEFAULT 10,
                        created_by INT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    )`,

                    // Tabla users
                    `CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(100) NOT NULL UNIQUE,
                        email VARCHAR(255) NOT NULL UNIQUE,
                        password VARCHAR(255) NOT NULL,
                        full_name VARCHAR(255) NOT NULL,
                        role ENUM('admin', 'user') DEFAULT 'user',
                        company_id INT,
                        is_active BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
                    )`,

                    // Tabla inventories
                    `CREATE TABLE IF NOT EXISTS inventories (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        description TEXT,
                        company_id INT NOT NULL,
                        created_by INT NOT NULL,
                        total_products INT DEFAULT 0,
                        counted_products INT DEFAULT 0,
                        progress_percentage DECIMAL(5,2) DEFAULT 0,
                        last_count_date TIMESTAMP NULL,
                        last_count_by INT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE,
                        FOREIGN KEY (created_by) REFERENCES users(id),
                        FOREIGN KEY (last_count_by) REFERENCES users(id)
                    )`,

                    // Tabla inventory_products
                    `CREATE TABLE IF NOT EXISTS inventory_products (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        inventory_id INT NOT NULL,
                        barcode VARCHAR(255) NOT NULL,
                        sku VARCHAR(100),
                        product_name VARCHAR(255),
                        expected_stock INT DEFAULT 0,
                        counted_stock INT DEFAULT NULL,
                        count_date TIMESTAMP NULL,
                        counted_by INT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        FOREIGN KEY (inventory_id) REFERENCES inventories(id) ON DELETE CASCADE,
                        FOREIGN KEY (counted_by) REFERENCES users(id),
                        UNIQUE KEY unique_barcode_per_inventory (inventory_id, barcode)
                    )`,

                    // Tabla user_inventories
                    `CREATE TABLE IF NOT EXISTS user_inventories (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT NOT NULL,
                        inventory_id INT NOT NULL,
                        can_edit BOOLEAN DEFAULT FALSE,
                        can_delete BOOLEAN DEFAULT FALSE,
                        can_upload BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                        FOREIGN KEY (inventory_id) REFERENCES inventories(id) ON DELETE CASCADE,
                        UNIQUE KEY unique_user_inventory (user_id, inventory_id)
                    )`
                ];

                for (let i = 0; i < tables.length; i++) {
                    await new Promise((resolve, reject) => {
                        connection.query(tables[i], (err) => {
                            if (err) {
                                console.error(`❌ Error creando tabla ${i + 1}:`, err.message);
                                reject(err);
                            } else {
                                console.log(`✅ Tabla ${i + 1} creada`);
                                resolve();
                            }
                        });
                    });
                }

                console.log('🎉 Base de datos inicializada exitosamente!');
                resolve();

            } catch (error) {
                console.error('❌ Error durante la inicialización:', error.message);
                reject(error);
            } finally {
                connection.end();
            }
        });
    });
}

// Ejecutar la inicialización
initializeDatabase().catch(console.error);
