-- Base de datos para el sistema de inventario
CREATE DATABASE IF NOT EXISTS inventory_system;
USE inventory_system;

-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role ENUM('admin', 'user') DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Tabla de inventarios
CREATE TABLE IF NOT EXISTS inventories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_by INT NOT NULL,
    status ENUM('created', 'counting', 'completed', 'cancelled') DEFAULT 'created',
    total_products INT DEFAULT 0,
    counted_products INT DEFAULT 0,
    progress_percentage DECIMAL(5,2) DEFAULT 0.00,
    last_count_date TIMESTAMP NULL,
    last_count_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (last_count_by) REFERENCES users(id)
);

-- Tabla de productos por inventario
CREATE TABLE IF NOT EXISTS inventory_products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    inventory_id INT NOT NULL,
    barcode VARCHAR(255) NOT NULL,
    sku VARCHAR(255) NULL,
    product_name VARCHAR(500) NULL,
    expected_stock INT DEFAULT 0,
    counted_stock INT DEFAULT 0,
    count_date TIMESTAMP NULL,
    counted_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (inventory_id) REFERENCES inventories(id) ON DELETE CASCADE,
    FOREIGN KEY (counted_by) REFERENCES users(id),
    UNIQUE KEY unique_barcode_inventory (inventory_id, barcode)
);

-- Insertar usuario admin por defecto
INSERT INTO users (username, email, password, full_name, role) 
VALUES ('admin', 'admin@inventory.com', '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Administrator', 'admin');
-- Password: password