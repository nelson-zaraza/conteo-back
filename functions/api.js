import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import mysql from 'mysql2/promise';
import multer from 'multer';
import XLSX from 'xlsx';
import path from 'path';
import { fileURLToPath } from 'url';
import nodemailer from 'nodemailer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'inventory_system',
    port: process.env.DB_PORT || 3306
};

// Configuración de Multer
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024
    }
});

// Middleware de autenticación MEJORADO para superadmin
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Token de acceso requerido' });
        }

        const decoded = jwt.verify(token, 'your-secret-key');
        const connection = await mysql.createConnection(dbConfig);

        const [users] = await connection.execute(
            `SELECT u.*, c.name as company_name, c.user_limit
             FROM users u
             LEFT JOIN companies c ON u.company_id = c.id
             WHERE u.id = ? AND u.is_active = TRUE`,
            [decoded.userId]
        );

        connection.end();

        if (users.length === 0) {
            return res.status(403).json({ error: 'Usuario no válido' });
        }

        req.user = users[0];
        next();
    } catch (error) {
        console.error('Token verification failed:', error.message);
        return res.status(403).json({ error: 'Token inválido' });
    }
};

// Middleware para verificar superadmin
const requireSuperAdmin = (req, res, next) => {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'Se requieren privilegios de superadministrador' });
    }
    next();
};

// ==============================================
// CONFIGURACIÓN DE EMAIL
// ==============================================

const EMAIL_CONFIG = {
  user: 'ingalexisarenas@gmail.com',
  pass: 'agef ie dd nbqi xnbm'.replace(/\s+/g, '')  // Contraseña SIN espacios
};

console.log('🔐 Configuración de email cargada:');
console.log('   Usuario:', EMAIL_CONFIG.user);
console.log('   Contraseña (limpia):', '*'.repeat(EMAIL_CONFIG.pass.length) + ` (${EMAIL_CONFIG.pass.length} caracteres)`);

const createTransporter = () => {
  try {
    console.log('🔄 Creando transporte de email REAL...');

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: EMAIL_CONFIG.user,
        pass: EMAIL_CONFIG.pass
      },
      debug: true,
      logger: false
    });

    // Verificar conexión inmediatamente
    transporter.verify(function(error, success) {
      if (error) {
        console.log('❌ Error verificando conexión con Gmail:', error.message);
        console.log('💡 Posibles soluciones:');
        console.log('   1. Verifica que la contraseña sea CORRECTA (sin espacios)');
        console.log('   2. Asegúrate de usar "Contraseña de aplicación" de Google');
        console.log('   3. Revisa que la verificación en 2 pasos esté ACTIVADA');
        console.log('   4. Genera una NUEVA contraseña si es necesario');
      } else {
        console.log('✅ ✅ ✅ CONEXIÓN CON GMAIL ESTABLECIDA ✅ ✅ ✅');
        console.log('📧 Listo para enviar emails REALES');
      }
    });

    return transporter;

  } catch (error) {
    console.error('❌ Error crítico creando transporter:', error.message);
    return null;
  }
};

const emailTransporter = createTransporter();

// Función para enviar emails
const sendEmail = async (mailOptions) => {
  console.log('\n📧 === INICIANDO ENVÍO DE EMAIL ===');
  console.log('   Para:', mailOptions.to);
  console.log('   Asunto:', mailOptions.subject);

  if (!emailTransporter) {
    console.log('❌ No hay transporte de email disponible');
    console.log('📧 === ENVÍO CANCELADO ===\n');
    return { success: false, error: 'Transporte no disponible' };
  }

  try {
    console.log('🚀 Enviando email REAL...');

    const result = await emailTransporter.sendMail({
      from: 'Sistema de Inventario <ingalexisarenas@gmail.com>',
      ...mailOptions
    });

    console.log('✅ ✅ ✅ EMAIL REAL ENVIADO EXITOSAMENTE ✅ ✅ ✅');
    console.log('   ID del mensaje:', result.messageId);
    console.log('   Respuesta:', result.response);
    console.log('📧 === EMAIL ENVIADO ===\n');

    return {
      success: true,
      messageId: result.messageId,
      response: result.response,
      real: true
    };

  } catch (error) {
    console.error('❌ ❌ ❌ ERROR ENVIANDO EMAIL REAL:');
    console.error('   Código:', error.code);
    console.error('   Mensaje:', error.message);

    if (error.code === 'EAUTH') {
      console.log('\n💡 PROBLEMA DE AUTENTICACIÓN:');
      console.log('   1. Verifica que usaste CONTRASEÑA DE APLICACIÓN (16 caracteres)');
      console.log('   2. NO uses tu contraseña normal de Gmail');
      console.log('   3. Asegúrate de que la verificación en 2 pasos esté ACTIVADA');
      console.log('   4. Genera una NUEVA contraseña en: https://myaccount.google.com/apppasswords');
    }

    if (error.code === 'EENVELOPE') {
      console.log('\n💡 PROBLEMA CON EL DESTINATARIO:');
      console.log('   Verifica que el email del destinatario sea válido');
    }

    console.log('📧 === ERROR EN ENVÍO ===\n');
    throw error;
  }
};

// ==============================================
// RUTAS DE SUPERADMIN
// ==============================================

// Obtener todas las empresas (solo superadmin)
app.get('/api/superadmin/companies', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);

        const [companies] = await connection.execute(`
            SELECT
                c.*,
                u.username as admin_username,
                u.full_name as admin_name,
                u.email as admin_email,
                (SELECT COUNT(*) FROM users u2 WHERE u2.company_id = c.id AND u2.is_active = TRUE) as user_count,
                (SELECT COUNT(*) FROM inventories i WHERE i.company_id = c.id) as inventory_count,
                (SELECT MAX(created_at) FROM users u3 WHERE u3.company_id = c.id) as last_activity
            FROM companies c
            LEFT JOIN users u ON c.created_by = u.id
            ORDER BY c.created_at DESC
        `);

        connection.end();

        res.json(companies);
    } catch (error) {
        console.error('Error getting companies:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Obtener estadísticas generales (solo superadmin)
app.get('/api/superadmin/stats', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);

        const [stats] = await connection.execute(`
            SELECT
                COUNT(DISTINCT c.id) as total_companies,
                COUNT(DISTINCT u.id) as total_users,
                COUNT(DISTINCT i.id) as total_inventories,
                COUNT(DISTINCT ip.id) as total_products,
                SUM(ip.counted_stock) as total_counted_units,
                SUM(ip.expected_stock) as total_expected_units,
                (SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = TRUE) as admin_users,
                (SELECT COUNT(*) FROM users WHERE role = 'user' AND is_active = TRUE) as regular_users
            FROM companies c
            LEFT JOIN users u ON c.id = u.company_id
            LEFT JOIN inventories i ON c.id = i.company_id
            LEFT JOIN inventory_products ip ON i.id = ip.inventory_id
        `);

        // Obtener actividad reciente
        const [recentActivity] = await connection.execute(`
            (SELECT 'user' as type, u.full_name, u.username, c.name as company_name, u.created_at as date
             FROM users u
             LEFT JOIN companies c ON u.company_id = c.id
             ORDER BY u.created_at DESC LIMIT 5)
            UNION ALL
            (SELECT 'inventory' as type, i.name as full_name, '' as username, c.name as company_name, i.created_at as date
             FROM inventories i
             LEFT JOIN companies c ON i.company_id = c.id
             ORDER BY i.created_at DESC LIMIT 5)
            ORDER BY date DESC LIMIT 10
        `);

        connection.end();

        res.json({
            overview: stats[0],
            recentActivity
        });
    } catch (error) {
        console.error('Error getting superadmin stats:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Crear nueva empresa (solo superadmin)
app.post('/api/superadmin/companies', authenticateToken, requireSuperAdmin, async (req, res) => {
    let connection;
    try {
        const { company_name, admin_username, admin_email, admin_full_name, admin_password, user_limit } = req.body;

        console.log('🏢 Creando nueva empresa:', { company_name, admin_username });

        if (!company_name || !admin_username || !admin_email || !admin_full_name || !admin_password) {
            return res.status(400).json({ error: 'Todos los campos son requeridos' });
        }

        connection = await mysql.createConnection(dbConfig);

        // Verificar si la empresa ya existe
        const [existingCompanies] = await connection.execute(
            'SELECT id FROM companies WHERE name = ?',
            [company_name]
        );

        if (existingCompanies.length > 0) {
            connection.end();
            return res.status(400).json({ error: 'El nombre de empresa ya existe' });
        }

        // Verificar si el usuario admin ya existe
        const [existingUsers] = await connection.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [admin_username, admin_email]
        );

        if (existingUsers.length > 0) {
            connection.end();
            return res.status(400).json({ error: 'El usuario o email ya existen' });
        }

        await connection.beginTransaction();

        try {
            // 1. Crear empresa
            const [companyResult] = await connection.execute(
                'INSERT INTO companies (name, user_limit, created_by) VALUES (?, ?, ?)',
                [company_name, user_limit || 10, req.user.id]
            );

            const companyId = companyResult.insertId;
            console.log('🏢 Empresa creada con ID:', companyId);

            // 2. Crear usuario admin
            const hashedPassword = await bcrypt.hash(admin_password, 10);
            const [userResult] = await connection.execute(
                'INSERT INTO users (username, email, password, full_name, role, company_id, is_active) VALUES (?, ?, ?, ?, "admin", ?, TRUE)',
                [admin_username, admin_email, hashedPassword, admin_full_name, companyId]
            );

            const userId = userResult.insertId;
            console.log('👤 Usuario administrador creado con ID:', userId);

            // 3. Actualizar empresa con created_by
            await connection.execute(
                'UPDATE companies SET created_by = ? WHERE id = ?',
                [userId, companyId]
            );

            await connection.commit();

            // Enviar correo de bienvenida
            try {
                const welcomeHtml = `
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset="utf-8">
                        <style>
                            body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }
                            .container { max-width: 600px; background: white; padding: 30px; border-radius: 10px; margin: 0 auto; }
                            .header { background: #8557FB; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
                            .content { padding: 20px; }
                            .credentials-box { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h1>¡Bienvenido a Sistema de Inventario!</h1>
                            </div>
                            <div class="content">
                                <p>Hola <strong>${admin_full_name}</strong>,</p>
                                <p>Tu empresa <strong>${company_name}</strong> ha sido registrada exitosamente.</p>

                                <div class="credentials-box">
                                    <h3>Detalles de tu cuenta:</h3>
                                    <p><strong>Usuario:</strong> ${admin_username}</p>
                                    <p><strong>Email:</strong> ${admin_email}</p>
                                    <p><strong>Contraseña:</strong> ${admin_password}</p>
                                    <p><strong>Límite de usuarios:</strong> ${user_limit || 10}</p>
                                </div>

                                <p>Ya puedes comenzar a gestionar tus inventarios de manera eficiente.</p>
                                <br>
                                <p>Saludos cordiales,<br>Equipo de Sistema de Inventario</p>
                            </div>
                        </div>
                    </body>
                    </html>
                `;

                await sendEmail({
                    to: admin_email,
                    subject: `🎉 ¡Bienvenido a Sistema de Inventario - ${company_name}!`,
                    html: welcomeHtml
                });
                console.log('✅ Correo de bienvenida enviado al administrador');
            } catch (emailError) {
                console.error('❌ Error enviando correo de bienvenida:', emailError);
            }

            connection.end();

            console.log('✅ Empresa creada exitosamente');

            res.json({
                success: true,
                message: 'Empresa y usuario administrador creados exitosamente',
                company_id: companyId,
                user_id: userId
            });

        } catch (error) {
            await connection.rollback();
            console.error('❌ Error en transacción:', error);
            throw error;
        }

    } catch (error) {
        console.error('❌ Error creando empresa:', error);
        if (connection) {
            try {
                await connection.rollback();
            } catch (rollbackError) {
                console.error('Error en rollback:', rollbackError);
            }
            connection.end();
        }
        res.status(500).json({ error: 'Error del servidor: ' + error.message });
    }
});

// Obtener usuarios de una empresa específica (solo superadmin)
app.get('/api/superadmin/companies/:companyId/users', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const companyId = req.params.companyId;
        const connection = await mysql.createConnection(dbConfig);

        const [users] = await connection.execute(`
            SELECT
                u.id, u.username, u.email, u.full_name, u.role, u.is_active,
                u.created_at, u.updated_at,
                (SELECT COUNT(*) FROM inventories i WHERE i.created_by = u.id) as created_inventories,
                (SELECT COUNT(*) FROM inventory_products ip WHERE ip.counted_by = u.id) as counted_products
            FROM users u
            WHERE u.company_id = ?
            ORDER BY u.created_at DESC
        `, [companyId]);

        connection.end();

        res.json(users);
    } catch (error) {
        console.error('Error getting company users:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Obtener inventarios de una empresa específica (solo superadmin)
app.get('/api/superadmin/companies/:companyId/inventories', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const companyId = req.params.companyId;
        const connection = await mysql.createConnection(dbConfig);

        const [inventories] = await connection.execute(`
            SELECT
                i.*,
                u.full_name as created_by_name,
                COALESCE(SUM(ip.expected_stock), 0) as total_units,
                COALESCE(SUM(ip.counted_stock), 0) as counted_units,
                COUNT(ip.id) as total_products,
                SUM(CASE WHEN ip.counted_stock IS NOT NULL AND ip.counted_stock > 0 THEN 1 ELSE 0 END) as counted_products
            FROM inventories i
            LEFT JOIN users u ON i.created_by = u.id
            LEFT JOIN inventory_products ip ON i.id = ip.inventory_id
            WHERE i.company_id = ?
            GROUP BY i.id
            ORDER BY i.created_at DESC
        `, [companyId]);

        connection.end();

        res.json(inventories);
    } catch (error) {
        console.error('Error getting company inventories:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Obtener logs de auditoría
app.get('/api/superadmin/audit-logs', authenticateToken, requireSuperAdmin, async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);

        const [logs] = await connection.execute(`
            (SELECT
                'login' as action_type,
                u.username,
                u.full_name,
                c.name as company_name,
                u.last_login as timestamp,
                u.last_login_ip as ip_address
             FROM users u
             LEFT JOIN companies c ON u.company_id = c.id
             WHERE u.last_login IS NOT NULL
             ORDER BY u.last_login DESC LIMIT 50)
            UNION ALL
            (SELECT
                'count' as action_type,
                u.username,
                u.full_name,
                c.name as company_name,
                ip.count_date as timestamp,
                NULL as ip_address
             FROM inventory_products ip
             LEFT JOIN users u ON ip.counted_by = u.id
             LEFT JOIN companies c ON u.company_id = c.id
             WHERE ip.count_date IS NOT NULL
             ORDER BY ip.count_date DESC LIMIT 50)
            ORDER BY timestamp DESC LIMIT 100
        `);

        connection.end();

        res.json(logs);
    } catch (error) {
        console.error('Error getting audit logs:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// ==============================================
// RUTAS DE GESTIÓN DE PERFIL (para todos los usuarios)
// ==============================================

// Obtener perfil del usuario actual
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);

        const [users] = await connection.execute(`
            SELECT
                u.id, u.username, u.email, u.full_name, u.role, u.company_id,
                c.name as company_name, u.created_at, u.last_login, u.last_login_ip
            FROM users u
            LEFT JOIN companies c ON u.company_id = c.id
            WHERE u.id = ?
        `, [req.user.id]);

        connection.end();

        if (users.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.json(users[0]);
    } catch (error) {
        console.error('Error getting profile:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Actualizar perfil del usuario
app.put('/api/profile', authenticateToken, async (req, res) => {
    let connection;
    try {
        const { full_name, email, current_password, new_password } = req.body;

        connection = await mysql.createConnection(dbConfig);

        // Verificar contraseña actual si se quiere cambiar la contraseña
        if (new_password) {
            if (!current_password) {
                connection.end();
                return res.status(400).json({ error: 'La contraseña actual es requerida' });
            }

            const [users] = await connection.execute(
                'SELECT password FROM users WHERE id = ?',
                [req.user.id]
            );

            if (users.length === 0) {
                connection.end();
                return res.status(404).json({ error: 'Usuario no encontrado' });
            }

            const isValidPassword = await bcrypt.compare(current_password, users[0].password);
            if (!isValidPassword) {
                connection.end();
                return res.status(400).json({ error: 'La contraseña actual es incorrecta' });
            }
        }

        // Construir query de actualización
        let updateQuery = 'UPDATE users SET full_name = ?, email = ?';
        let queryParams = [full_name, email];

        if (new_password) {
            const hashedPassword = await bcrypt.hash(new_password, 10);
            updateQuery += ', password = ?';
            queryParams.push(hashedPassword);
        }

        updateQuery += ' WHERE id = ?';
        queryParams.push(req.user.id);

        await connection.execute(updateQuery, queryParams);
        connection.end();

        res.json({
            success: true,
            message: 'Perfil actualizado exitosamente'
        });
    } catch (error) {
        if (connection) connection.end();
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// ==============================================
// RUTAS EXISTENTES (se mantienen igual)
// ==============================================

// Registro de empresa y admin - CORREGIDO
app.post('/api/register', async (req, res) => {
    let connection;
    try {
        const { company_name, username, email, password, full_name } = req.body;

        console.log('📝 Intentando registro:', { company_name, username, email, full_name });

        if (!company_name || !username || !email || !password || !full_name) {
            return res.status(400).json({ error: 'Todos los campos son requeridos' });
        }

        connection = await mysql.createConnection(dbConfig);

        // Verificar si el usuario o email ya existen
        const [existingUsers] = await connection.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existingUsers.length > 0) {
            connection.end();
            return res.status(400).json({ error: 'El usuario o email ya existen' });
        }

        // Verificar si la empresa ya existe
        const [existingCompanies] = await connection.execute(
            'SELECT id FROM companies WHERE name = ?',
            [company_name]
        );

        if (existingCompanies.length > 0) {
            connection.end();
            return res.status(400).json({ error: 'El nombre de empresa ya existe' });
        }

        await connection.beginTransaction();

        try {
            // 1. Crear empresa (sin created_by por ahora)
            const [companyResult] = await connection.execute(
                'INSERT INTO companies (name, user_limit) VALUES (?, ?)',
                [company_name, 10]
            );

            const companyId = companyResult.insertId;
            console.log('🏢 Empresa creada con ID:', companyId);

            // 2. Crear usuario admin
            const hashedPassword = await bcrypt.hash(password, 10);
            const [userResult] = await connection.execute(
                'INSERT INTO users (username, email, password, full_name, role, company_id, is_active) VALUES (?, ?, ?, ?, "admin", ?, TRUE)',
                [username, email, hashedPassword, full_name, companyId]
            );

            const userId = userResult.insertId;
            console.log('👤 Usuario administrador creado con ID:', userId);

            // 3. Actualizar empresa con created_by (si la columna existe)
            try {
                await connection.execute(
                    'UPDATE companies SET created_by = ? WHERE id = ?',
                    [userId, companyId]
                );
                console.log('✅ Campo created_by actualizado en empresa');
            } catch (updateError) {
                // Si falla la actualización, continuar sin problema
                console.log('ℹ️ Columna created_by no disponible, continuando...');
            }

            await connection.commit();

            // Enviar correo de bienvenida al admin con sus credenciales REALES
            try {
                const welcomeHtml = `
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset="utf-8">
                        <style>
                            body {
                                font-family: 'Arial', sans-serif;
                                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                margin: 0;
                                padding: 40px 20px;
                                min-height: 100vh;
                            }
                            .container {
                                max-width: 600px;
                                background: white;
                                padding: 0;
                                border-radius: 15px;
                                margin: 0 auto;
                                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                                overflow: hidden;
                            }
                            .header {
                                background: linear-gradient(135deg, #8557FB 0%, #6A32F2 100%);
                                color: white;
                                padding: 40px;
                                text-align: center;
                            }
                            .header h1 {
                                margin: 0;
                                font-size: 32px;
                                font-weight: 700;
                            }
                            .content {
                                padding: 40px 30px;
                                color: #333;
                            }
                            .credentials-box {
                                background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                                padding: 25px;
                                border-radius: 10px;
                                margin: 25px 0;
                                border-left: 4px solid #28a745;
                            }
                            .feature {
                                background: white;
                                padding: 15px;
                                margin: 10px 0;
                                border-radius: 8px;
                                border-left: 3px solid #8557FB;
                            }
                            .button {
                                display: inline-block;
                                background: linear-gradient(135deg, #8557FB 0%, #6A32F2 100%);
                                color: white;
                                padding: 15px 35px;
                                text-decoration: none;
                                border-radius: 25px;
                                margin: 20px 0;
                                font-weight: 600;
                                font-size: 16px;
                            }
                            .footer {
                                text-align: center;
                                margin-top: 30px;
                                padding-top: 20px;
                                border-top: 1px solid #eee;
                                color: #666;
                                font-size: 14px;
                            }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h1>🎉 ¡Bienvenido a Sistema de Inventario!</h1>
                                <p style="margin: 10px 0 0 0; opacity: 0.9;">Gestión profesional de inventarios</p>
                            </div>
                            <div class="content">
                                <p>Hola <strong>${full_name}</strong>,</p>
                                <p>¡Excelentes noticias! Tu empresa <strong>${company_name}</strong> ha sido registrada exitosamente en nuestro sistema.</p>

                                <div class="credentials-box">
                                    <h3 style="margin-top: 0; color: #28a745;">✅ Tus Credenciales de Acceso</h3>
                                    <p><strong>🏢 Empresa:</strong> ${company_name}</p>
                                    <p><strong>👤 Usuario:</strong> ${username}</p>
                                    <p><strong>🔑 Contraseña:</strong> ${password}</p>
                                    <p><strong>📧 Email:</strong> ${email}</p>
                                    <p><strong>👑 Rol:</strong> Administrador</p>
                                    <p><strong>👥 Límite de usuarios:</strong> 10</p>
                                </div>

                                <div style="margin: 30px 0;">
                                    <h3 style="color: #8557FB;">🚀 Comienza ahora mismo</h3>
                                    <div class="feature">
                                        <strong>📦 Conteo de inventarios</strong> - Crea y organiza tus conteos
                                    </div>
                                    <div class="feature">
                                        <strong>👥 Administra usuarios</strong> - Asigna permisos a tu equipo
                                    </div>
                                    <div class="feature">
                                        <strong>📊 Genera reportes</strong> - Exporta datos en Excel
                                    </div>
                                    <div class="feature">
                                        <strong>📱 Escanea códigos</strong> - Conteo rápido con código de barras
                                    </div>
                                </div>

                                <div style="text-align: center;">
                                    <a href="#" class="button">Comenzar a Usar el Sistema</a>
                                </div>

                                <p style="text-align: center; color: #666; font-style: italic;">
                                    "La mejor manera de predecir el futuro es crearlo"
                                </p>
                            </div>
                            <div class="footer">
                                <p>Equipo de Sistema de Conteo de Inventario<br>
                                <small>Si tienes alguna pregunta, estamos aquí para ayudarte.</small></p>
                            </div>
                        </div>
                    </body>
                    </html>
                `;

                await sendEmail({
                    to: email,
                    subject: `🎉 ¡Bienvenido a Sistema de Inventario - ${company_name}!`,
                    html: welcomeHtml
                });
                console.log('✅ Correo de bienvenida enviado al administrador');
            } catch (emailError) {
                console.error('❌ Error enviando correo de bienvenida:', emailError);
                // No fallar el registro si el email falla
            }

            // Generar token JWT
            const token = jwt.sign(
                { userId: userId, username: username },
                'your-secret-key',
                { expiresIn: '24h' }
            );

            const userData = {
                id: userId,
                username: username,
                email: email,
                full_name: full_name,
                role: 'admin',
                company_id: companyId,
                company_name: company_name,
                user_limit: 10
            };

            console.log('✅ Registro completado exitosamente');

            res.json({
                success: true,
                token,
                user: userData,
                message: 'Empresa y usuario administrador creados exitosamente'
            });

        } catch (error) {
            await connection.rollback();
            console.error('❌ Error en transacción:', error);
            throw error;
        }

    } catch (error) {
        console.error('❌ Error en registro:', error);
        if (connection) {
            try {
                await connection.rollback();
            } catch (rollbackError) {
                console.error('Error en rollback:', rollbackError);
            }
        }
        res.status(500).json({ error: 'Error del servidor: ' + error.message });
    } finally {
        if (connection) connection.end();
    }
});

// Login
app.post('/api/login', async (req, res) => {
    let connection;
    try {
        const { username, password } = req.body;

        console.log('🔐 Login attempt for:', username);

        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
        }

        connection = await mysql.createConnection(dbConfig);

        const [users] = await connection.execute(
            `SELECT u.*, c.name as company_name, c.user_limit
             FROM users u
             LEFT JOIN companies c ON u.company_id = c.id
             WHERE u.username = ? AND u.is_active = TRUE`,
            [username]
        );

        if (users.length === 0) {
            connection.end();
            console.log('❌ Usuario no encontrado:', username);
            return res.status(401).json({ error: 'Usuario no encontrado' });
        }

        const user = users[0];
        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
            connection.end();
            console.log('❌ Contraseña incorrecta para:', username);
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username },
            'your-secret-key',
            { expiresIn: '24h' }
        );

        const userData = {
            id: user.id,
            username: user.username,
            email: user.email,
            full_name: user.full_name,
            role: user.role,
            company_id: user.company_id,
            company_name: user.company_name,
            user_limit: user.user_limit
        };

        console.log('🎉 Login successful for:', username);

        res.json({
            success: true,
            token,
            user: userData
        });
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Error del servidor: ' + error.message });
    } finally {
        if (connection) connection.end();
    }
});

// Obtener información de la empresa
app.get('/api/company', authenticateToken, async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);

        const [companies] = await connection.execute(
            `SELECT c.*, COUNT(u.id) as current_users
             FROM companies c
             LEFT JOIN users u ON c.id = u.company_id AND u.is_active = TRUE
             WHERE c.id = ?
             GROUP BY c.id`,
            [req.user.company_id]
        );

        connection.end();

        if (companies.length === 0) {
            return res.status(404).json({ error: 'Empresa no encontrada' });
        }

        res.json(companies[0]);
    } catch (error) {
        console.error('Error getting company:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Obtener inventarios según el rol del usuario
app.get('/api/inventories', authenticateToken, async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);

        let query, params;

        if (req.user.role === 'admin') {
            query = `
                SELECT
                    i.*,
                    u.full_name as created_by_name,
                    COALESCE(SUM(ip.expected_stock), 0) as total_units,
                    COALESCE(SUM(ip.counted_stock), 0) as counted_units,
                    COUNT(ip.id) as total_products,
                    SUM(CASE WHEN ip.counted_stock IS NOT NULL AND ip.counted_stock > 0 THEN 1 ELSE 0 END) as counted_products,
                    CASE
                        WHEN COALESCE(SUM(ip.expected_stock), 0) > 0 THEN
                            (COALESCE(SUM(ip.counted_stock), 0) / COALESCE(SUM(ip.expected_stock), 0)) * 100
                        ELSE 0
                    END as progress_percentage
                FROM inventories i
                LEFT JOIN users u ON i.created_by = u.id
                LEFT JOIN inventory_products ip ON i.id = ip.inventory_id
                WHERE i.company_id = ?
                GROUP BY i.id, i.name, i.description, i.created_by, i.created_at, i.updated_at, u.full_name
                ORDER BY i.created_at DESC
            `;
            params = [req.user.company_id];
        } else {
            query = `
                SELECT
                    i.*,
                    u.full_name as created_by_name,
                    COALESCE(SUM(ip.expected_stock), 0) as total_units,
                    COALESCE(SUM(ip.counted_stock), 0) as counted_units,
                    COUNT(ip.id) as total_products,
                    SUM(CASE WHEN ip.counted_stock IS NOT NULL AND ip.counted_stock > 0 THEN 1 ELSE 0 END) as counted_products,
                    CASE
                        WHEN COALESCE(SUM(ip.expected_stock), 0) > 0 THEN
                            (COALESCE(SUM(ip.counted_stock), 0) / COALESCE(SUM(ip.expected_stock), 0)) * 100
                        ELSE 0
                    END as progress_percentage,
                    ui.can_edit,
                    ui.can_delete,
                    ui.can_upload
                FROM user_inventories ui
                INNER JOIN inventories i ON ui.inventory_id = i.id
                LEFT JOIN users u ON i.created_by = u.id
                LEFT JOIN inventory_products ip ON i.id = ip.inventory_id
                WHERE ui.user_id = ? AND i.company_id = ?
                GROUP BY i.id, i.name, i.description, i.created_by, i.created_at, i.updated_at, u.full_name, ui.can_edit, ui.can_delete, ui.can_upload
                ORDER BY i.created_at DESC
            `;
            params = [req.user.id, req.user.company_id];
        }

        const [inventories] = await connection.execute(query, params);
        connection.end();

        console.log(`Found ${inventories.length} inventories for user: ${req.user.id}`);
        res.json(inventories);
    } catch (error) {
        console.error('Error getting inventories:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Obtener un inventario específico
app.get('/api/inventories/:id', authenticateToken, async (req, res) => {
    try {
        const inventoryId = req.params.id;
        const connection = await mysql.createConnection(dbConfig);

        let query, params;

        if (req.user.role === 'admin') {
            query = `
                SELECT i.*, u.full_name as created_by_name
                FROM inventories i
                LEFT JOIN users u ON i.created_by = u.id
                WHERE i.id = ? AND i.company_id = ?
            `;
            params = [inventoryId, req.user.company_id];
        } else {
            query = `
                SELECT i.*, u.full_name as created_by_name, ui.can_edit, ui.can_delete, ui.can_upload
                FROM user_inventories ui
                INNER JOIN inventories i ON ui.inventory_id = i.id
                LEFT JOIN users u ON i.created_by = u.id
                WHERE ui.user_id = ? AND i.id = ? AND i.company_id = ?
            `;
            params = [req.user.id, inventoryId, req.user.company_id];
        }

        const [inventories] = await connection.execute(query, params);

        if (inventories.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Inventario no encontrado' });
        }

        connection.end();
        res.json(inventories[0]);
    } catch (error) {
        console.error('Error getting inventory:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Crear inventario
app.post('/api/inventories', authenticateToken, async (req, res) => {
    try {
        const { name, description } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({ error: 'El nombre del inventario es requerido' });
        }

        const connection = await mysql.createConnection(dbConfig);

        const [result] = await connection.execute(
            'INSERT INTO inventories (name, description, company_id, created_by) VALUES (?, ?, ?, ?)',
            [name.trim(), description, req.user.company_id, req.user.id]
        );

        connection.end();

        console.log(`Inventory created with ID: ${result.insertId}`);

        res.json({
            success: true,
            id: result.insertId,
            message: 'Inventario creado exitosamente'
        });
    } catch (error) {
        console.error('Error creating inventory:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Actualizar inventario
app.put('/api/inventories/:id', authenticateToken, async (req, res) => {
    try {
        const inventoryId = req.params.id;
        const { name, description } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({ error: 'El nombre es requerido' });
        }

        const connection = await mysql.createConnection(dbConfig);

        let query, params;

        if (req.user.role === 'admin') {
            query = 'SELECT * FROM inventories WHERE id = ? AND company_id = ?';
            params = [inventoryId, req.user.company_id];
        } else {
            query = `
                SELECT i.* FROM user_inventories ui
                INNER JOIN inventories i ON ui.inventory_id = i.id
                WHERE ui.user_id = ? AND i.id = ? AND ui.can_edit = TRUE
            `;
            params = [req.user.id, inventoryId];
        }

        const [inventories] = await connection.execute(query, params);

        if (inventories.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Inventario no encontrado o sin permisos' });
        }

        await connection.execute(
            'UPDATE inventories SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [name.trim(), description, inventoryId]
        );

        connection.end();

        console.log(`Inventory updated: ${inventoryId}`);

        res.json({
            success: true,
            message: 'Inventario actualizado exitosamente'
        });
    } catch (error) {
        console.error('Error updating inventory:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Eliminar inventario
app.delete('/api/inventories/:id', authenticateToken, async (req, res) => {
    try {
        const inventoryId = req.params.id;
        const connection = await mysql.createConnection(dbConfig);

        let query, params;

        if (req.user.role === 'admin') {
            query = 'SELECT * FROM inventories WHERE id = ? AND company_id = ?';
            params = [inventoryId, req.user.company_id];
        } else {
            query = `
                SELECT i.* FROM user_inventories ui
                INNER JOIN inventories i ON ui.inventory_id = i.id
                WHERE ui.user_id = ? AND i.id = ? AND ui.can_delete = TRUE
            `;
            params = [req.user.id, inventoryId];
        }

        const [inventories] = await connection.execute(query, params);

        if (inventories.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Inventario no encontrado o sin permisos' });
        }

        await connection.execute('DELETE FROM inventory_products WHERE inventory_id = ?', [inventoryId]);
        await connection.execute('DELETE FROM user_inventories WHERE inventory_id = ?', [inventoryId]);
        await connection.execute('DELETE FROM inventories WHERE id = ?', [inventoryId]);

        connection.end();

        console.log(`Inventory deleted successfully: ${inventoryId}`);

        res.json({
            success: true,
            message: 'Inventario eliminado exitosamente'
        });
    } catch (error) {
        console.error('Error deleting inventory:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Cargar productos desde Excel
app.post('/api/inventories/:id/upload', authenticateToken, upload.single('file'), async (req, res) => {
    let connection;
    try {
        const inventoryId = req.params.id;
        const file = req.file;

        if (!file) {
            return res.status(400).json({ error: 'No se proporcionó archivo' });
        }

        connection = await mysql.createConnection(dbConfig);

        let query, params;

        if (req.user.role === 'admin') {
            query = 'SELECT * FROM inventories WHERE id = ? AND company_id = ?';
            params = [inventoryId, req.user.company_id];
        } else {
            query = `
                SELECT i.* FROM user_inventories ui
                INNER JOIN inventories i ON ui.inventory_id = i.id
                WHERE ui.user_id = ? AND i.id = ? AND ui.can_upload = TRUE
            `;
            params = [req.user.id, inventoryId];
        }

        const [inventories] = await connection.execute(query, params);

        if (inventories.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Inventario no encontrado o sin permisos' });
        }

        const workbook = XLSX.read(file.buffer, { type: 'buffer' });
        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];
        const data = XLSX.utils.sheet_to_json(worksheet);

        if (data.length === 0) {
            connection.end();
            return res.status(400).json({ error: 'El archivo está vacío' });
        }

        const columnNames = Object.keys(data[0]);
        console.log('Excel columns:', columnNames);

        const barcodeKey = columnNames.find(key =>
            key.toLowerCase().includes('barcode') ||
            key.toLowerCase().includes('codigo') ||
            key.toLowerCase().includes('código') ||
            key.toLowerCase().includes('ean') ||
            key.toLowerCase().includes('upc') ||
            key.toLowerCase().includes('sku')
        );

        if (!barcodeKey) {
            connection.end();
            return res.status(400).json({
                error: 'El archivo debe contener una columna de código de barras'
            });
        }

        let processed = 0;
        let errors = 0;
        const errorsList = [];

        console.log(`Processing ${data.length} rows...`);

        for (const [index, row] of data.entries()) {
            try {
                const barcode = row[barcodeKey] ? String(row[barcodeKey]).trim() : null;

                if (!barcode) {
                    errors++;
                    errorsList.push(`Fila ${index + 2}: Sin código de barras`);
                    continue;
                }

                const skuKey = columnNames.find(key => key.toLowerCase().includes('sku'));
                const nameKey = columnNames.find(key =>
                    key.toLowerCase().includes('name') ||
                    key.toLowerCase().includes('nombre') ||
                    key.toLowerCase().includes('producto')
                );
                const stockKey = columnNames.find(key =>
                    key.toLowerCase().includes('stock') ||
                    key.toLowerCase().includes('cantidad')
                );

                await connection.execute(
                    `INSERT INTO inventory_products
                    (inventory_id, barcode, sku, product_name, expected_stock)
                    VALUES (?, ?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE
                    sku = VALUES(sku), product_name = VALUES(product_name), expected_stock = VALUES(expected_stock)`,
                    [
                        inventoryId,
                        barcode,
                        skuKey && row[skuKey] ? String(row[skuKey]) : null,
                        nameKey && row[nameKey] ? String(row[nameKey]) : null,
                        stockKey && row[stockKey] ? parseInt(row[stockKey]) || 0 : 0
                    ]
                );
                processed++;
            } catch (rowError) {
                errors++;
                errorsList.push(`Fila ${index + 2}: ${rowError.message}`);
            }
        }

        await connection.execute(
            'UPDATE inventories SET total_products = ? WHERE id = ?',
            [processed, inventoryId]
        );

        connection.end();

        console.log(`File processed: ${processed} success, ${errors} errors`);

        const response = {
            success: true,
            message: `Se procesaron ${processed} productos exitosamente`,
            processed,
            errors,
            totalRows: data.length
        };

        if (errors > 0) {
            response.errorDetails = errorsList.slice(0, 10);
        }

        res.json(response);
    } catch (error) {
        if (connection) connection.end();
        console.error('Error processing file:', error);
        res.status(500).json({ error: 'Error procesando archivo: ' + error.message });
    }
});

// Buscar producto por código de barras
app.get('/api/inventories/:id/products/search', authenticateToken, async (req, res) => {
    try {
        const { barcode } = req.query;
        const inventoryId = req.params.id;

        if (!barcode || barcode.trim().length < 1) {
            return res.status(400).json({ error: 'Código de barras requerido' });
        }

        const connection = await mysql.createConnection(dbConfig);

        let query, params;

        if (req.user.role === 'admin') {
            query = 'SELECT * FROM inventories WHERE id = ? AND company_id = ?';
            params = [inventoryId, req.user.company_id];
        } else {
            query = `
                SELECT i.* FROM user_inventories ui
                INNER JOIN inventories i ON ui.inventory_id = i.id
                WHERE ui.user_id = ? AND i.id = ? AND i.company_id = ?
            `;
            params = [req.user.id, inventoryId, req.user.company_id];
        }

        const [inventories] = await connection.execute(query, params);

        if (inventories.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Inventario no encontrado' });
        }

        const searchTerm = `%${barcode.trim()}%`;
        const [products] = await connection.execute(
            `SELECT * FROM inventory_products
             WHERE inventory_id = ? AND barcode LIKE ?
             ORDER BY
                 CASE
                     WHEN barcode = ? THEN 1
                     WHEN barcode LIKE ? THEN 2
                     ELSE 3
                 END,
                 barcode
             LIMIT 10`,
            [inventoryId, searchTerm, barcode.trim(), `${barcode.trim()}%`]
        );

        connection.end();
        res.json(products);
    } catch (error) {
        console.error('Error searching product:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Obtener todos los productos del inventario
app.get('/api/inventories/:id/products', authenticateToken, async (req, res) => {
    try {
        const inventoryId = req.params.id;
        const connection = await mysql.createConnection(dbConfig);

        let query, params;

        if (req.user.role === 'admin') {
            query = 'SELECT * FROM inventories WHERE id = ? AND company_id = ?';
            params = [inventoryId, req.user.company_id];
        } else {
            query = `
                SELECT i.* FROM user_inventories ui
                INNER JOIN inventories i ON ui.inventory_id = i.id
                WHERE ui.user_id = ? AND i.id = ? AND i.company_id = ?
            `;
            params = [req.user.id, inventoryId, req.user.company_id];
        }

        const [inventories] = await connection.execute(query, params);

        if (inventories.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Inventario no encontrado' });
        }

        const [products] = await connection.execute(`
            SELECT
                ip.*,
                u.full_name as counted_by_name,
                CASE
                    WHEN ip.counted_stock IS NULL OR ip.counted_stock = 0 THEN 'not-counted'
                    WHEN ip.counted_stock > ip.expected_stock THEN 'excess'
                    WHEN ip.counted_stock < ip.expected_stock THEN 'shortage'
                    ELSE 'exact'
                END as status,
                (ip.counted_stock - ip.expected_stock) as difference,
                CASE
                    WHEN ip.expected_stock > 0 THEN
                        ROUND(((ip.counted_stock - ip.expected_stock) / ip.expected_stock) * 100, 2)
                    ELSE 0
                END as difference_percentage,
                CASE
                    WHEN ip.expected_stock > 0 THEN
                        ROUND((ip.counted_stock / ip.expected_stock) * 100, 2)
                    ELSE 0
                END as progress_percentage
            FROM inventory_products ip
            LEFT JOIN users u ON ip.counted_by = u.id
            WHERE ip.inventory_id = ?
            ORDER BY ip.product_name, ip.barcode
        `, [inventoryId]);

        connection.end();
        res.json(products);
    } catch (error) {
        console.error('Error getting products:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Registrar conteo
app.post('/api/inventories/:id/count', authenticateToken, async (req, res) => {
    let connection;
    try {
        const inventoryId = req.params.id;
        const { barcode, quantity } = req.body;

        if (!barcode || !barcode.trim()) {
            return res.status(400).json({ error: 'Código de barras requerido' });
        }

        if (quantity === undefined || quantity === null || quantity < 0) {
            return res.status(400).json({ error: 'Cantidad válida requerida' });
        }

        connection = await mysql.createConnection(dbConfig);

        let query, params;

        if (req.user.role === 'admin') {
            query = 'SELECT * FROM inventories WHERE id = ? AND company_id = ?';
            params = [inventoryId, req.user.company_id];
        } else {
            query = `
                SELECT i.* FROM user_inventories ui
                INNER JOIN inventories i ON ui.inventory_id = i.id
                WHERE ui.user_id = ? AND i.id = ? AND i.company_id = ?
            `;
            params = [req.user.id, inventoryId, req.user.company_id];
        }

        const [inventories] = await connection.execute(query, params);

        if (inventories.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Inventario no encontrado' });
        }

        // Buscar el producto
        const [products] = await connection.execute(
            'SELECT * FROM inventory_products WHERE inventory_id = ? AND barcode = ?',
            [inventoryId, barcode.trim()]
        );

        let productId;
        let newCountedStock;

        if (products.length === 0) {
            const [insertResult] = await connection.execute(
                'INSERT INTO inventory_products (inventory_id, barcode, counted_stock, count_date, counted_by) VALUES (?, ?, ?, NOW(), ?)',
                [inventoryId, barcode.trim(), quantity, req.user.id]
            );
            productId = insertResult.insertId;
            newCountedStock = quantity;
        } else {
            productId = products[0].id;
            newCountedStock = (products[0].counted_stock || 0) + quantity;

            await connection.execute(
                `UPDATE inventory_products
                 SET counted_stock = ?, count_date = NOW(), counted_by = ?
                 WHERE inventory_id = ? AND barcode = ?`,
                [newCountedStock, req.user.id, inventoryId, barcode.trim()]
            );
        }

        // Obtener el producto actualizado
        const [updatedProducts] = await connection.execute(
            `SELECT
                ip.*,
                u.full_name as counted_by_name,
                CASE
                    WHEN ip.counted_stock IS NULL OR ip.counted_stock = 0 THEN 'not-counted'
                    WHEN ip.counted_stock > ip.expected_stock THEN 'excess'
                    WHEN ip.counted_stock < ip.expected_stock THEN 'shortage'
                    ELSE 'exact'
                END as status,
                (ip.counted_stock - ip.expected_stock) as difference,
                CASE
                    WHEN ip.expected_stock > 0 THEN
                        ROUND(((ip.counted_stock - ip.expected_stock) / ip.expected_stock) * 100, 2)
                    ELSE 0
                END as difference_percentage,
                CASE
                    WHEN ip.expected_stock > 0 THEN
                        ROUND((ip.counted_stock / ip.expected_stock) * 100, 2)
                    ELSE 0
                END as progress_percentage
             FROM inventory_products ip
             LEFT JOIN users u ON ip.counted_by = u.id
             WHERE ip.id = ?`,
            [productId]
        );

        const updatedProduct = updatedProducts[0];

        // Obtener estadísticas del inventario
        const [stats] = await connection.execute(`
            SELECT
                COUNT(*) as total_products,
                SUM(CASE WHEN counted_stock IS NOT NULL AND counted_stock > 0 THEN 1 ELSE 0 END) as counted_products,
                COALESCE(SUM(expected_stock), 0) as total_units,
                COALESCE(SUM(counted_stock), 0) as counted_units,
                CASE
                    WHEN COUNT(*) > 0 THEN
                        (SUM(CASE WHEN counted_stock IS NOT NULL AND counted_stock > 0 THEN 1 ELSE 0 END) / COUNT(*)) * 100
                    ELSE 0
                END as progress_percentage
            FROM inventory_products
            WHERE inventory_id = ?
        `, [inventoryId]);

        // Actualizar inventario
        await connection.execute(
            `UPDATE inventories
             SET total_products = ?, counted_products = ?, progress_percentage = ?,
                 last_count_date = NOW(), last_count_by = ?, updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`,
            [stats[0].total_products, stats[0].counted_products, stats[0].progress_percentage, req.user.id, inventoryId]
        );

        connection.end();

        console.log(`Count registered successfully - added ${quantity} to product ${barcode}`);

        res.json({
            success: true,
            message: 'Conteo registrado exitosamente',
            product: updatedProduct,
            inventoryStats: {
                progress: stats[0].progress_percentage,
                total_products: stats[0].total_products,
                counted_products: stats[0].counted_products
            }
        });
    } catch (error) {
        if (connection) connection.end();
        console.error('Error registering count:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Exportar inventario
app.get('/api/inventories/:id/export', authenticateToken, async (req, res) => {
    let connection;
    try {
        const inventoryId = req.params.id;
        const format = req.query.format || 'excel';
        const type = req.query.type || 'all';

        connection = await mysql.createConnection(dbConfig);

        let query, params;

        if (req.user.role === 'admin') {
            query = 'SELECT * FROM inventories WHERE id = ? AND company_id = ?';
            params = [inventoryId, req.user.company_id];
        } else {
            query = `
                SELECT i.* FROM user_inventories ui
                INNER JOIN inventories i ON ui.inventory_id = i.id
                WHERE ui.user_id = ? AND i.id = ? AND i.company_id = ?
            `;
            params = [req.user.id, inventoryId, req.user.company_id];
        }

        const [inventories] = await connection.execute(query, params);

        if (inventories.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Inventario no encontrado' });
        }

        const inventory = inventories[0];

        // Construir query según el tipo
        let productsQuery = `
            SELECT
                barcode,
                sku,
                product_name,
                expected_stock,
                counted_stock,
                count_date,
                CASE
                    WHEN counted_stock IS NOT NULL AND counted_stock > 0 THEN 'CONTADO'
                    ELSE 'PENDIENTE'
                END as status,
                CASE
                    WHEN expected_stock IS NOT NULL AND counted_stock IS NOT NULL
                    THEN counted_stock - expected_stock
                    ELSE NULL
                END as diferencia
            FROM inventory_products
            WHERE inventory_id = ?
        `;

        const queryParams = [inventoryId];

        switch (type) {
            case 'excess':
                productsQuery += ' AND counted_stock > expected_stock';
                break;
            case 'shortage':
                productsQuery += ' AND counted_stock < expected_stock AND counted_stock > 0';
                break;
            case 'not-counted':
                productsQuery += ' AND (counted_stock IS NULL OR counted_stock = 0)';
                break;
            case 'counted':
                productsQuery += ' AND counted_stock > 0';
                break;
            case 'differences':
                productsQuery += ' AND counted_stock != expected_stock AND counted_stock > 0';
                break;
        }

        productsQuery += ' ORDER BY barcode';

        const [products] = await connection.execute(productsQuery, queryParams);
        connection.end();

        if (products.length === 0) {
            return res.status(404).json({ error: 'No se encontraron productos para exportar' });
        }

        if (format === 'csv') {
            const csvHeaders = ['Código Barras', 'SKU', 'Producto', 'Stock Esperado', 'Stock Contado', 'Diferencia', 'Estado', 'Fecha Conteo'];
            const csvData = products.map(product => [
                product.barcode || '',
                product.sku || '',
                product.product_name || '',
                product.expected_stock || 0,
                product.counted_stock || 0,
                product.diferencia || 0,
                product.status || '',
                product.count_date ? new Date(product.count_date).toLocaleDateString('es-ES') : ''
            ]);

            const csvContent = [
                csvHeaders.join(','),
                ...csvData.map(row => row.map(field => `"${field}"`).join(','))
            ].join('\n');

            const typeNames = {
                'all': 'completo',
                'excess': 'excesos',
                'shortage': 'faltantes',
                'not-counted': 'no_contados',
                'counted': 'contados',
                'differences': 'diferencias'
            };

            const filename = `inventario_${typeNames[type]}_${inventory.name}_${new Date().toISOString().split('T')[0]}.csv`;

            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.send(csvContent);

        } else {
            const workbook = XLSX.utils.book_new();

            const worksheetData = [
                ['Código Barras', 'SKU', 'Producto', 'Stock Esperado', 'Stock Contado', 'Diferencia', 'Estado', 'Fecha Conteo'],
                ...products.map(product => [
                    product.barcode || '',
                    product.sku || '',
                    product.product_name || '',
                    product.expected_stock || 0,
                    product.counted_stock || 0,
                    product.diferencia || 0,
                    product.status || '',
                    product.count_date ? new Date(product.count_date).toLocaleDateString('es-ES') : ''
                ])
            ];

            const worksheet = XLSX.utils.aoa_to_sheet(worksheetData);

            if (worksheet['!ref']) {
                const range = XLSX.utils.decode_range(worksheet['!ref']);
                for (let col = range.s.c; col <= range.e.c; col++) {
                    const cellAddress = XLSX.utils.encode_cell({ r: 0, c: col });
                    if (!worksheet[cellAddress].s) {
                        worksheet[cellAddress].s = {
                            font: { bold: true, color: { rgb: "FFFFFF" } },
                            fill: { fgColor: { rgb: "4472C4" } },
                            alignment: { horizontal: "center" }
                        };
                    }
                }
            }

            XLSX.utils.book_append_sheet(workbook, worksheet, 'Inventario');

            const typeNames = {
                'all': 'completo',
                'excess': 'excesos',
                'shortage': 'faltantes',
                'not-counted': 'no_contados',
                'counted': 'contados',
                'differences': 'diferencias'
            };

            const now = new Date();
            const timestamp = now.toISOString().slice(0,19).replace(/:/g, '-');
            const filename = `inventario_${typeNames[type]}_${inventory.name}_${timestamp}.xlsx`;

            const excelBuffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });

            res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.send(excelBuffer);
        }

    } catch (error) {
        if (connection) connection.end();
        console.error('Error exporting inventory:', error);
        res.status(500).json({ error: 'Error exportando inventario: ' + error.message });
    }
});

// Gestión de usuarios (solo admin)
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'No tienes permisos para acceder a esta función' });
        }

        const connection = await mysql.createConnection(dbConfig);
        const [users] = await connection.execute(`
            SELECT id, username, email, full_name, role, is_active, created_at, updated_at
            FROM users
            WHERE company_id = ?
            ORDER BY created_at DESC
        `, [req.user.company_id]);

        connection.end();

        res.json(users);
    } catch (error) {
        console.error('Error getting users:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

app.post('/api/users', authenticateToken, async (req, res) => {
    let connection;
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'No tienes permisos para crear usuarios' });
        }

        const { username, email, password, full_name, role } = req.body;

        if (!username || !email || !password || !full_name) {
            return res.status(400).json({ error: 'Todos los campos son requeridos' });
        }

        connection = await mysql.createConnection(dbConfig);

        // Verificar límite de usuarios
        const [userCount] = await connection.execute(
            'SELECT COUNT(*) as count FROM users WHERE company_id = ? AND is_active = TRUE',
            [req.user.company_id]
        );

        const [company] = await connection.execute(
            'SELECT user_limit FROM companies WHERE id = ?',
            [req.user.company_id]
        );

        if (userCount[0].count >= company[0].user_limit) {
            connection.end();
            return res.status(400).json({
                error: `Límite de usuarios alcanzado. Máximo permitido: ${company[0].user_limit}`
            });
        }

        // Verificar si el usuario o email ya existen
        const [existingUsers] = await connection.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existingUsers.length > 0) {
            connection.end();
            return res.status(400).json({ error: 'El usuario o email ya existen' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await connection.execute(
            'INSERT INTO users (username, email, password, full_name, role, company_id, is_active) VALUES (?, ?, ?, ?, ?, ?, TRUE)',
            [username, email, hashedPassword, full_name, role || 'user', req.user.company_id]
        );

        // Enviar correo con las credenciales REALES al nuevo usuario
        try {
            const credentialsHtml = `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <style>
                        body {
                            font-family: 'Arial', sans-serif;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            margin: 0;
                            padding: 40px 20px;
                            min-height: 100vh;
                        }
                        .container {
                            max-width: 600px;
                            background: white;
                            padding: 0;
                            border-radius: 15px;
                            margin: 0 auto;
                            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                            overflow: hidden;
                        }
                        .header {
                            background: linear-gradient(135deg, #8557FB 0%, #6A32F2 100%);
                            color: white;
                            padding: 30px;
                            text-align: center;
                        }
                        .header h1 {
                            margin: 0;
                            font-size: 28px;
                            font-weight: 700;
                        }
                        .content {
                            padding: 40px 30px;
                            color: #333;
                        }
                        .credentials-box {
                            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                            padding: 25px;
                            border-radius: 10px;
                            margin: 25px 0;
                            border-left: 4px solid #28a745;
                        }
                        .feature {
                            background: white;
                            padding: 12px;
                            margin: 8px 0;
                            border-radius: 6px;
                            border-left: 3px solid #8557FB;
                        }
                        .button {
                            display: inline-block;
                            background: linear-gradient(135deg, #8557FB 0%, #6A32F2 100%);
                            color: white;
                            padding: 12px 30px;
                            text-decoration: none;
                            border-radius: 25px;
                            margin: 15px 0;
                            font-weight: 600;
                        }
                        .footer {
                            text-align: center;
                            margin-top: 30px;
                            padding-top: 20px;
                            border-top: 1px solid #eee;
                            color: #666;
                            font-size: 14px;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>👤 Tu Cuenta ha sido Creada</h1>
                            <p style="margin: 10px 0 0 0; opacity: 0.9;">${req.user.company_name}</p>
                        </div>
                        <div class="content">
                            <p>Hola <strong>${full_name}</strong>,</p>
                            <p>Se ha creado una cuenta para ti en nuestro Sistema de Conteo de Inventario.</p>

                            <div class="credentials-box">
                                <h3 style="margin-top: 0; color: #28a745;">🔐 Tus Credenciales de Acceso</h3>
                                <p><strong>🏢 Empresa:</strong> ${req.user.company_name}</p>
                                <p><strong>👤 Usuario:</strong> ${username}</p>
                                <p><strong>🔑 Contraseña:</strong> ${password}</p>
                                <p><strong>📧 Email:</strong> ${email}</p>
                                <p><strong>👑 Rol:</strong> ${role === 'admin' ? 'Administrador' : 'Usuario'}</p>
                            </div>

                            <div style="margin: 25px 0;">
                                <h3 style="color: #8557FB;">🚀 Comienza a Usar el Sistema</h3>
                                <div class="feature">
                                    <strong>📦 Conteo de tus Inventarios</strong> - Realiza conteos y seguimiento
                                </div>
                                <div class="feature">
                                    <strong>📊 Ver Reportes</strong> - Consulta estadísticas y progreso
                                </div>
                                ${role === 'admin' ? `
                                <div class="feature">
                                    <strong>👥 Administrar Usuarios</strong> - Gestiona acceso del equipo
                                </div>
                                <div class="feature">
                                    <strong>⚙️ Configurar Sistema</strong> - Personaliza la plataforma
                                </div>
                                ` : ''}
                            </div>

                            <div style="text-align: center;">
                                <a href="#" class="button">Iniciar Sesión en el Sistema</a>
                            </div>

                            <p style="text-align: center; color: #666; font-style: italic; margin-top: 25px;">
                                "El trabajo en equipo divide el trabajo y multiplica los resultados"
                            </p>
                        </div>
                        <div class="footer">
                            <p>Equipo de Sistema de Inventario - ${req.user.company_name}<br>
                            <small>Este es un mensaje automático, por favor no respondas a este correo.</small></p>
                        </div>
                    </div>
                </body>
                </html>
            `;

            await sendEmail({
                to: email,
                subject: `👤 Tu cuenta en Sistema de Inventario - ${req.user.company_name}`,
                html: credentialsHtml
            });
            console.log('✅ Credenciales enviadas al nuevo usuario');
        } catch (emailError) {
            console.error('❌ Error enviando credenciales:', emailError);
            // No fallar la creación si el email falla
        }

        connection.end();

        console.log(`Usuario creado - Credenciales enviadas:`, { username, password });

        res.json({
            success: true,
            message: 'Usuario creado exitosamente',
            id: result.insertId
        });
    } catch (error) {
        if (connection) connection.end();
        console.error('Error creating user:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
    let connection;
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'No tienes permisos para editar usuarios' });
        }

        const userId = req.params.id;
        const { username, email, password, full_name, role, is_active } = req.body;

        connection = await mysql.createConnection(dbConfig);

        // Verificar si el usuario existe y pertenece a la empresa
        const [existingUsers] = await connection.execute(
            'SELECT id FROM users WHERE id = ? AND company_id = ?',
            [userId, req.user.company_id]
        );

        if (existingUsers.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        // Verificar si el nuevo username o email ya existen
        const [duplicateUsers] = await connection.execute(
            'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ? AND company_id = ?',
            [username, email, userId, req.user.company_id]
        );

        if (duplicateUsers.length > 0) {
            connection.end();
            return res.status(400).json({ error: 'El usuario o email ya existen' });
        }

        let updateQuery = 'UPDATE users SET username = ?, email = ?, full_name = ?, role = ?, is_active = ?';
        let queryParams = [username, email, full_name, role, is_active];

        if (password && password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(password, 10);
            updateQuery += ', password = ?';
            queryParams.push(hashedPassword);
        }

        updateQuery += ' WHERE id = ?';
        queryParams.push(userId);

        await connection.execute(updateQuery, queryParams);
        connection.end();

        res.json({
            success: true,
            message: 'Usuario actualizado exitosamente'
        });
    } catch (error) {
        if (connection) connection.end();
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Gestión de inventarios por usuario
app.get('/api/users/:id/available-inventories', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'No tienes permisos para acceder a esta función' });
        }

        const userId = req.params.id;
        const connection = await mysql.createConnection(dbConfig);

        // Verificar que el usuario pertenece a la misma empresa
        const [users] = await connection.execute(
            'SELECT id FROM users WHERE id = ? AND company_id = ?',
            [userId, req.user.company_id]
        );

        if (users.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        const [inventories] = await connection.execute(`
            SELECT i.*
            FROM inventories i
            WHERE i.company_id = ?
            AND i.id NOT IN (
                SELECT inventory_id
                FROM user_inventories
                WHERE user_id = ?
            )
            ORDER BY i.name
        `, [req.user.company_id, userId]);

        connection.end();

        res.json(inventories);
    } catch (error) {
        console.error('Error getting available inventories:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

app.get('/api/users/:id/assigned-inventories', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'No tienes permisos para acceder a esta función' });
        }

        const userId = req.params.id;
        const connection = await mysql.createConnection(dbConfig);

        const [users] = await connection.execute(
            'SELECT id FROM users WHERE id = ? AND company_id = ?',
            [userId, req.user.company_id]
        );

        if (users.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        const [inventories] = await connection.execute(`
            SELECT i.*, ui.can_edit, ui.can_delete, ui.can_upload
            FROM user_inventories ui
            INNER JOIN inventories i ON ui.inventory_id = i.id
            WHERE ui.user_id = ?
            ORDER BY i.name
        `, [userId]);

        connection.end();

        res.json(inventories);
    } catch (error) {
        console.error('Error getting assigned inventories:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

app.post('/api/users/:userId/assign-inventory/:inventoryId', authenticateToken, async (req, res) => {
    let connection;
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'No tienes permisos para realizar esta acción' });
        }

        const { userId, inventoryId } = req.params;
        const { can_edit, can_delete, can_upload } = req.body;

        connection = await mysql.createConnection(dbConfig);

        // Verificar que tanto usuario como inventario pertenecen a la misma empresa
        const [validation] = await connection.execute(`
            SELECT u.id as user_id, i.id as inventory_id
            FROM users u
            CROSS JOIN inventories i
            WHERE u.id = ? AND i.id = ? AND u.company_id = ? AND i.company_id = ?
        `, [userId, inventoryId, req.user.company_id, req.user.company_id]);

        if (validation.length === 0) {
            connection.end();
            return res.status(404).json({ error: 'Usuario o inventario no encontrado' });
        }

        await connection.execute(
            `INSERT INTO user_inventories (user_id, inventory_id, can_edit, can_delete, can_upload)
             VALUES (?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
             can_edit = VALUES(can_edit),
             can_delete = VALUES(can_delete),
             can_upload = VALUES(can_upload)`,
            [userId, inventoryId, can_edit || false, can_delete || false, can_upload || false]
        );

        connection.end();

        res.json({
            success: true,
            message: 'Inventario asignado exitosamente'
        });
    } catch (error) {
        if (connection) connection.end();
        console.error('Error assigning inventory:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

app.delete('/api/users/:userId/assign-inventory/:inventoryId', authenticateToken, async (req, res) => {
    let connection;
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'No tienes permisos para realizar esta acción' });
        }

        const { userId, inventoryId } = req.params;

        connection = await mysql.createConnection(dbConfig);

        await connection.execute(
            'DELETE FROM user_inventories WHERE user_id = ? AND inventory_id = ?',
            [userId, inventoryId]
        );

        connection.end();

        res.json({
            success: true,
            message: 'Asignación removida exitosamente'
        });
    } catch (error) {
        if (connection) connection.end();
        console.error('Error removing inventory assignment:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Ruta para enviar correos
app.post('/api/email/send', authenticateToken, async (req, res) => {
  try {
    const { to, subject, html } = req.body;
    console.log('📧 Solicitando envío a:', to);

    const result = await sendEmail({ to, subject, html });

    if (result.success) {
      res.json({
        success: true,
        message: 'Correo enviado exitosamente',
        messageId: result.messageId
      });
    } else {
      res.status(500).json({
        success: false,
        error: result.error || 'Error enviando correo'
      });
    }
  } catch (error) {
    console.error('❌ Error en API de email:', error.message);
    res.status(500).json({
      success: false,
      error: 'Error enviando correo: ' + error.message
    });
  }
});

// Eliminar usuario (solo admin)
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  let connection;
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'No tienes permisos para eliminar usuarios' });
    }

    const userId = req.params.id;

    // No permitir eliminar el propio usuario
    if (parseInt(userId) === req.user.id) {
      return res.status(400).json({ error: 'No puedes eliminar tu propio usuario' });
    }

    connection = await mysql.createConnection(dbConfig);

    // Verificar que el usuario existe y pertenece a la misma empresa
    const [existingUsers] = await connection.execute(
      'SELECT id FROM users WHERE id = ? AND company_id = ?',
      [userId, req.user.company_id]
    );

    if (existingUsers.length === 0) {
      connection.end();
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // En lugar de eliminar físicamente, marcamos como inactivo
    await connection.execute(
      'UPDATE users SET is_active = FALSE WHERE id = ?',
      [userId]
    );

    connection.end();

    console.log(`Usuario desactivado: ${userId}`);

    res.json({
      success: true,
      message: 'Usuario desactivado exitosamente'
    });
  } catch (error) {
    if (connection) connection.end();
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// Ruta para recuperación de contraseña - VERSIÓN DEFINITIVA
app.post('/api/forgot-password', async (req, res) => {
  let connection;
  try {
    const { email } = req.body;
    console.log('🔑 Solicitud de recuperación para:', email);

    if (!email) {
      return res.status(400).json({ error: 'Email es requerido' });
    }

    connection = await mysql.createConnection(dbConfig);

    // Buscar usuario
    const [users] = await connection.execute(
      `SELECT u.*, c.name as company_name
       FROM users u
       LEFT JOIN companies c ON u.company_id = c.id
       WHERE u.email = ? AND u.is_active = TRUE`,
      [email]
    );

    // Siempre responder éxito por seguridad
    if (users.length === 0) {
      connection.end();
      console.log('📧 Email no encontrado, pero respondiendo con éxito por seguridad');
      return res.json({
        success: true,
        message: 'Si el email existe en nuestro sistema, se enviaron las instrucciones'
      });
    }

    const user = users[0];

    // ✅ GENERAR CONTRASEÑA TEMPORAL NUEVA
    const temporaryPassword = Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8);
    console.log('🔐 Contraseña temporal generada:', temporaryPassword);

    // ✅ HASHEAR LA NUEVA CONTRASEÑA
    const hashedPassword = await bcrypt.hash(temporaryPassword, 10);

    // ✅ ACTUALIZAR LA CONTRASEÑA EN LA BASE DE DATOS
    await connection.execute(
      'UPDATE users SET password = ? WHERE id = ?',
      [hashedPassword, user.id]
    );

    console.log('✅ Contraseña temporal actualizada en la base de datos');

    // HTML del correo de recuperación - VERSIÓN QUE SÍ ENVÍA LA CONTRASEÑA
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 40px 20px;
            min-height: 100vh;
          }
          .container {
            max-width: 600px;
            background: white;
            padding: 0;
            border-radius: 15px;
            margin: 0 auto;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
          }
          .header {
            background: linear-gradient(135deg, #8557FB 0%, #6A32F2 100%);
            color: white;
            padding: 30px;
            text-align: center;
          }
          .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 700;
          }
          .content {
            padding: 40px 30px;
            color: #333;
          }
          .user-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin: 25px 0;
            border-left: 4px solid #8557FB;
          }
          .password-box {
            background: #e8f5e8;
            border: 2px dashed #28a745;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            text-align: center;
            font-size: 18px;
            font-weight: bold;
            color: #155724;
          }
          .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 20px;
            border-radius: 10px;
            margin: 25px 0;
            color: #856404;
          }
          .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #666;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Recuperación de Contraseña</h1>
          </div>
          <div class="content">
            <p>Hola <strong>${user.full_name}</strong>,</p>
            <p>Has solicitado recuperar el acceso a tu cuenta en nuestro Sistema de Inventario.</p>

            <div class="user-info">
              <h3 style="margin-top: 0; color: #8557FB;">Información de tu cuenta:</h3>
              <p><strong>👤 Usuario:</strong> ${user.username}</p>
              <p><strong>🏢 Empresa:</strong> ${user.company_name}</p>
              <p><strong>📧 Email:</strong> ${user.email}</p>
            </div>

            <div class="password-box">
              <h3 style="margin-top: 0; color: #155724;">Tu Nueva Contraseña Temporal</h3>
              <div style="font-size: 24px; letter-spacing: 2px; margin: 15px 0; background: white; padding: 15px; border-radius: 8px; border: 2px solid #28a745;">
                ${temporaryPassword}
              </div>
              <p style="margin: 10px 0 0 0; font-size: 14px; font-weight: normal;">
                Usa esta contraseña para iniciar sesión
              </p>
            </div>

            <div class="warning">
              <h4 style="margin-top: 0;">⚠️ Importante de Seguridad</h4>
              <p>Por seguridad, te recomendamos <strong>cambiar esta contraseña temporal</strong> después de iniciar sesión.</p>
              <p>Esta contraseña es válida por 24 horas.</p>
            </div>

            <p>Si no solicitaste este correo, por favor contacta al administrador de inmediato.</p>
          </div>
          <div class="footer">
            <p>Equipo de Sistema de Inventario<br>
            <small>Este es un mensaje automático, por favor no respondas a este correo.</small></p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Enviar email
    console.log('📧 Enviando email con contraseña temporal...');
    const emailResult = await sendEmail({
      to: email,
      subject: '🔐 Recuperación de contraseña - Sistema de Inventario',
      html: html
    });

    connection.end();

    console.log('✅ Proceso de recuperación completado para:', email);
    console.log('🔐 Contraseña temporal enviada:', temporaryPassword);

    res.json({
      success: true,
      message: 'Se ha enviado un correo con una contraseña temporal'
    });

  } catch (error) {
    if (connection) connection.end();
    console.error('❌ Error en recuperación:', error);
    // Por seguridad, siempre responder éxito
    res.json({
      success: true,
      message: 'Si el email existe en nuestro sistema, se han enviado las instrucciones'
    });
  }
});

// Health check
app.get('/api/health', async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);
        await connection.execute('SELECT 1');
        connection.end();

        res.json({
            status: 'OK',
            message: 'Servidor y base de datos funcionando correctamente',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            status: 'ERROR',
            message: 'Error en la base de datos: ' + error.message
        });
    }
});

// app.listen(PORT, () => {
//     console.log(`Servidor corriendo en puerto ${PORT}`);
//     console.log(`Sistema de Inventario con SuperAdmin`);
//     console.log(`Health check: http://localhost:${PORT}/api/health`);
// });
