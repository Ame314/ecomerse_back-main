const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("../config/database");

// Clave secreta para JWT, obtenida de variables de entorno
const JWT_SECRET = process.env.JWT_SECRET || "mi_secreto_jwt";

// Registro de usuario
const register = async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    // Verificar si el email ya está registrado
    const queryEmail = `SELECT id FROM users WHERE email = ?`;
    const [existingUser] = await pool.query(queryEmail, [email]);

    if (existingUser.length > 0) {
      return res.status(400).json({ message: "El email ya está registrado" });
    }

    // Encriptar la contraseña
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insertar el nuevo usuario en la base de datos
    const queryInsert = `
      INSERT INTO users (username, email, password, role) 
      VALUES (?, ?, ?, ?)
    `;
    const [result] = await pool.query(queryInsert, [
      username,
      email,
      hashedPassword,
      role || "user", // Si no se especifica, toma "user" como valor predeterminado
    ]);

    // Retornar la información del usuario creado
    return res.status(201).json({
      id: result.insertId,
      username,
      email,
      role: role || "user",
    });
  } catch (error) {
    console.error("Error al registrar usuario:", error);
    return res.status(500).json({ message: "Error al registrar usuario" });
  }
};

// Inicio de sesión
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Verificar si existe el usuario
    const queryUser = `
      SELECT id, username, email, password, role 
      FROM users 
      WHERE email = ?
    `;
    const [users] = await pool.query(queryUser, [email]);

    if (users.length === 0) {
      return res.status(400).json({ message: "Usuario o contraseña inválida" });
    }

    const user = users[0];

    // Comparar contraseñas
    const esValida = await bcrypt.compare(password, user.password);
    if (!esValida) {
      return res.status(400).json({ message: "Usuario o contraseña inválida" });
    }

    // Crear token
    const token = jwt.sign(
      {
        userId: user.id,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "1d" } // Token válido por 1 día
    );

    // Retornar info del usuario (sin la contraseña) y el token
    return res.json({
      message: "Login exitoso",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Error al iniciar sesión:", error);
    return res.status(500).json({ message: "Error al iniciar sesión" });
  }
};

module.exports = {
  register,
  login,
};
