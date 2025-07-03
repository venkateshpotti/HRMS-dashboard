// --- Imports ---
const express = require('express');
const { Pool, Client } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

// --- Configuration ---
const app = express();
const PORT = process.env.PORT || 3000;
const dbName = process.env.DB_DATABASE || 'dashboard_db';

// --- Database Connection Pool ---
const dbConfig = { user: process.env.DB_USER || 'postgres', host: process.env.DB_HOST || 'localhost', password: process.env.DB_PASSWORD, port: process.env.DB_PORT || 5432 };
let pool;

// --- Database Table Initialization ---
async function initializeDatabase() {
    const mainClient = new Client({ ...dbConfig, database: 'postgres' });
    try {
        await mainClient.connect();
        const res = await mainClient.query(`SELECT 1 FROM pg_database WHERE datname = $1`, [dbName]);
        if (res.rowCount === 0) {
            console.log(`Database '${dbName}' not found. Creating...`);
            await mainClient.query(`CREATE DATABASE ${dbName}`);
            console.log(`Database '${dbName}' created successfully.`);
        } else {
            console.log(`Database '${dbName}' already exists.`);
        }
    } catch (err) {
        console.error('FATAL: Error during database check/creation. Is PostgreSQL running and are .env credentials correct?', err);
        process.exit(1);
    } finally {
        await mainClient.end();
    }

    const appPool = new Pool({ ...dbConfig, database: dbName });
    try {
        await appPool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(50) NOT NULL, employee_id VARCHAR(50) UNIQUE NOT NULL, email VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL)`);
        await appPool.query(`CREATE TABLE IF NOT EXISTS attendance (id SERIAL PRIMARY KEY, employee_id VARCHAR(50) NOT NULL, punch_in_time TIMESTAMPTZ NOT NULL, punch_out_time TIMESTAMPTZ, session_password_hash VARCHAR(255) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'PUNCH_IN')`);
        await appPool.query(`CREATE TABLE IF NOT EXISTS leaves (id SERIAL PRIMARY KEY, employee_name VARCHAR(255) NOT NULL, employee_id VARCHAR(50) NOT NULL, email VARCHAR(255) NOT NULL, leave_type VARCHAR(50) NOT NULL, from_date DATE NOT NULL, to_date DATE NOT NULL, reason TEXT NOT NULL, status VARCHAR(20) DEFAULT 'Pending', applied_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        await appPool.query(`CREATE TABLE IF NOT EXISTS wfh_requests (id SERIAL PRIMARY KEY, employee_id VARCHAR(50) NOT NULL, name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, project VARCHAR(255), manager VARCHAR(255), location VARCHAR(255) NOT NULL, from_date DATE NOT NULL, to_date DATE NOT NULL, reason TEXT NOT NULL, status VARCHAR(20) DEFAULT 'Pending', applied_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        await appPool.query(`CREATE TABLE IF NOT EXISTS jobs (id SERIAL PRIMARY KEY, job_title VARCHAR(255) NOT NULL, job_description TEXT NOT NULL, required_skills TEXT NOT NULL, required_experience VARCHAR(100) NOT NULL, job_type VARCHAR(50) NOT NULL, location VARCHAR(255) NOT NULL, salary_range VARCHAR(100) NOT NULL, application_deadline DATE NOT NULL, posted_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        await appPool.query(`CREATE TABLE IF NOT EXISTS payslips (id SERIAL PRIMARY KEY, employee_id VARCHAR(50) NOT NULL, employee_name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, start_month DATE NOT NULL, end_month DATE, status VARCHAR(20) DEFAULT 'Pending', applied_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        await appPool.query(`CREATE TABLE IF NOT EXISTS work_submissions (id SERIAL PRIMARY KEY, task_name VARCHAR(255) NOT NULL, employee_name VARCHAR(255) NOT NULL, employee_id VARCHAR(50) NOT NULL, document_filename VARCHAR(255) NOT NULL, status VARCHAR(50) NOT NULL, submitted_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        //await appPool.query(`CREATE TABLE IF NOT EXISTS tasks (id SERIAL PRIMARY KEY,employee_id VARCHAR(50) NOT NULL,description TEXT NOT NULL,completed BOOLEAN DEFAULT FALSE,created_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        await appPool.query(`CREATE TABLE IF NOT EXISTS banking_details (id SERIAL PRIMARY KEY, employee_id VARCHAR(50) NOT NULL UNIQUE, bank_name VARCHAR(255) NOT NULL, account_holder_name VARCHAR(255) NOT NULL, account_number VARCHAR(50) NOT NULL, ifsc_code VARCHAR(20) NOT NULL, account_type VARCHAR(50) NOT NULL)`);
        await appPool.query(`CREATE TABLE IF NOT EXISTS help_desk_tickets (id SERIAL PRIMARY KEY,employee_id VARCHAR(50) NOT NULL,employee_name VARCHAR(255) NOT NULL,email VARCHAR(255) NOT NULL,category VARCHAR(50) NOT NULL,priority VARCHAR(20) NOT NULL,subject VARCHAR(255) NOT NULL,description TEXT NOT NULL,status VARCHAR(20) DEFAULT 'Open',submitted_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        console.log("✅ All database tables are ready.");
        return appPool;
    } catch (err) {
        console.error('FATAL: Error creating tables:', err);
        process.exit(1);
    }
}

// --- Middleware ---
app.use(cors());
app.use(express.json());
// Serve static files from 'public' directory, e.g., /login serves public/login.html
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
// Serve partials from 'public/partials' directory
app.use('/partials', express.static(path.join(__dirname, 'public/partials')));


// --- JWT Authentication Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ message: 'No token provided' });
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = decoded;
        next();
    });
};

// --- Page Routes ---
app.get('/', (req, res) => res.redirect('/login'));

// --- API Endpoints ---
app.post('/api/signup', async (req, res) => {
    const { username, employee_id, email, password } = req.body;
    if (!username || !employee_id || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
    if (!/^[A-Z]{3}0[0-9]{3}$/i.test(employee_id)) return res.status(400).json({ message: 'Invalid Employee ID format (e.g., ATS001).' });
    try {
        const hash = await bcrypt.hash(password, 10);
        await pool.query("INSERT INTO users (username, employee_id, email, password_hash) VALUES ($1, $2, $3, $4)", [username, employee_id.toUpperCase(), email, hash]);
        res.status(201).json({ message: 'User created successfully!' });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ message: 'Employee ID or Email already registered.' });
        res.status(500).json({ message: 'Server error during signup.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        const token = jwt.sign({ id: user.id, empId: user.employee_id }, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, username: user.username, employee_id: user.employee_id });
    } catch (err) { 
        res.status(500).json({ message: 'A server error occurred during login.' }); 
    }
});

app.post('/api/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) return res.status(400).json({ message: 'Email and new password are required.' });
    try {
        const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (userResult.rowCount === 0) return res.status(404).json({ message: 'User with that email does not exist.' });
        const hash = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [hash, email]);
        res.status(200).json({ message: 'Password has been reset successfully!' });
    } catch (err) {
        res.status(500).json({ message: 'An error occurred on the server.' });
    }
});

app.get('/api/user/me', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT username, employee_id, email FROM users WHERE id = $1', [req.user.id]);
        if (rows.length === 0) return res.status(404).json({ message: 'User not found.' });
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ message: 'Server error fetching user details.' });
    }
});

// --- ATTENDANCE ENDPOINTS ---

// [FIXED] ADDED ENDPOINT TO CHECK CURRENT PUNCH STATUS
app.get('/api/status/:employeeId', authenticateToken, async (req, res) => {
    if (req.user.empId !== req.params.employeeId.toUpperCase()) {
        return res.status(403).json({ message: 'Forbidden: You can only check your own status.' });
    }
    try {
        const { rows } = await pool.query(
            "SELECT id FROM attendance WHERE employee_id = $1 AND status = 'PUNCH_IN'",
            [req.user.empId]
        );
        res.json({ punchedIn: rows.length > 0 });
    } catch (err) {
        console.error('[STATUS CHECK ERROR]', err);
        res.status(500).json({ message: 'Server error checking status.' });
    }
});

// [FIXED] ADDED ENDPOINT TO GET LOGGED-IN USER'S ATTENDANCE HISTORY
app.get('/api/my-attendance', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query(
            "SELECT * FROM attendance WHERE employee_id = $1 ORDER BY punch_in_time DESC",
            [req.user.empId]
        );
        res.json(rows);
    } catch (err) {
        console.error('[ATTENDANCE HISTORY ERROR]', err);
        res.status(500).json({ message: 'Server error fetching attendance history.' });
    }
});

app.post('/api/punch', authenticateToken, async (req, res) => {
    const { employeeId, password } = req.body;
    const upperId = employeeId && employeeId.toUpperCase();

    if (!upperId || req.user.empId !== upperId) {
        return res.status(403).json({ message: 'Forbidden: You can only punch for yourself.' });
    }
    if (!password) return res.status(400).json({ message: 'Password required.' });

    try {
        const { rows } = await pool.query(
            "SELECT id, session_password_hash FROM attendance WHERE employee_id = $1 AND status = 'PUNCH_IN'",
            [upperId]
        );

        if (rows.length > 0) {
            if (!(await bcrypt.compare(password, rows[0].session_password_hash))) {
                return res.status(401).json({ message: 'Invalid session password.' });
            }
            await pool.query(
                "UPDATE attendance SET punch_out_time = NOW(), status = 'PUNCH_OUT' WHERE id = $1",
                [rows[0].id]
            );
            res.json({ message: `Punched out ${upperId}!` });
        } else {
            const hash = await bcrypt.hash(password, 10);
            await pool.query(
                "INSERT INTO attendance (employee_id, punch_in_time, session_password_hash, status) VALUES ($1, NOW(), $2, 'PUNCH_IN')",
                [upperId, hash]
            );
            res.status(201).json({ message: `Punched in ${upperId}!` });
        }
    } catch (err) {
        console.error('[ATTENDANCE ERROR]', err);
        res.status(500).json({ message: 'Server error during attendance.' });
    }
});

// --- LEAVE ENDPOINTS ---

// [FIXED] ADDED ENDPOINT TO GET A USER'S LEAVE HISTORY
app.get('/api/leaves/:employeeId', authenticateToken, async (req, res) => {
    const requestedEmpId = req.params.employeeId.toUpperCase();
    if (req.user.empId !== requestedEmpId) {
        return res.status(403).json({ message: 'Forbidden: You can only view your own leave history.' });
    }
    try {
        const { rows } = await pool.query(
            "SELECT * FROM leaves WHERE employee_id = $1 ORDER BY applied_on DESC",
            [requestedEmpId]
        );
        res.json(rows);
    } catch (err) {
        console.error('[LEAVE HISTORY ERROR]', err);
        res.status(500).json({ message: 'Server error fetching leave history.' });
    }
});

app.post('/api/leaves', authenticateToken, async (req, res) => {
    const { employee_name, employee_id, email, leave_type, from_date, to_date, reason } = req.body;
    if (req.user.empId !== employee_id.toUpperCase()) return res.status(403).json({ message: 'Forbidden: You can only submit leave for yourself.' });
    try {
        await pool.query("INSERT INTO leaves (employee_name, employee_id, email, leave_type, from_date, to_date, reason) VALUES ($1, $2, $3, $4, $5, $6, $7)", [employee_name, employee_id.toUpperCase(), email, leave_type, from_date, to_date, reason]);
        res.status(201).json({ message: 'Leave request submitted successfully!' });
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

// --- WFH ENDPOINT ---

app.post('/api/wfh-requests', authenticateToken, async (req, res) => {
    const { name, employee_id, email, project, manager, location, from_date, to_date, reason } = req.body;
    
    // [FIXED] ADDED SECURITY CHECK AND MISSING FIELDS CHECK
    if (req.user.empId !== employee_id.toUpperCase()) {
        return res.status(403).json({ message: 'Forbidden: You can only submit WFH requests for yourself.' });
    }
    if (!name || !employee_id || !email || !location || !from_date || !to_date || !reason) {
        return res.status(400).json({ message: 'Missing required fields.' });
    }

    try {
        const query = `INSERT INTO wfh_requests (name, employee_id, email, project, manager, location, from_date, to_date, reason) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`;
        const values = [name, employee_id.toUpperCase(), email, project || null, manager || null, location, from_date, to_date, reason];
        await pool.query(query, values);
        res.status(201).json({ message: 'WFH request submitted successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'An error occurred on the server while submitting your request.' });
    }
});

// --- OTHER ENDPOINTS ---

app.post('/api/jobs', authenticateToken, async (req, res) => {
    const { jobTitle, jobDescription, requiredSkills, requiredExperience, jobType, location, salaryRange, applicationDeadline } = req.body;
    if (!jobTitle || !jobDescription || !requiredSkills || !requiredExperience || !jobType || !location || !salaryRange || !applicationDeadline) {
        return res.status(400).json({ error: 'All required fields must be filled.' });
    }
    try {
        const query = `INSERT INTO jobs (job_title, job_description, required_skills, required_experience, job_type, location, salary_range, application_deadline) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`;
        const values = [jobTitle, jobDescription, requiredSkills, requiredExperience, jobType, location, salaryRange, applicationDeadline];
        await pool.query(query, values);
        res.status(201).json({ message: 'Job posted successfully!'});
    } catch (error) {
        res.status(500).json({ error: 'An error occurred on the server while posting the job.' });
    }
});

app.post('/api/payslip', authenticateToken, async (req, res) => {
    const { employeeName, employeeId, email, password, startMonth, endMonth } = req.body;
    if (!employeeName || !employeeId || !email || !password || !startMonth) {
        return res.status(400).json({ error: "Missing required fields." });
    }
    if (req.user.empId !== employeeId.toUpperCase()) {
        return res.status(403).json({ error: 'Forbidden: You can only request your own payslip.' });
    }
    try {
        const userResult = await pool.query('SELECT password_hash FROM users WHERE employee_id = $1', [employeeId.toUpperCase()]);
        if (userResult.rowCount === 0) return res.status(404).json({ error: 'Employee not found.' });
        const isPasswordMatch = await bcrypt.compare(password, userResult.rows[0].password_hash);
        if (!isPasswordMatch) return res.status(401).json({ error: 'Invalid password.' });

        const startDate = `${startMonth}-01`;
        const endDate = endMonth ? `${endMonth}-01` : null;

        const query = `INSERT INTO payslips (employee_id, employee_name, email, start_month, end_month) VALUES ($1, $2, $3, $4, $5) RETURNING id`;
        const values = [employeeId.toUpperCase(), employeeName, email, startDate, endDate];
        await pool.query(query, values);
        res.status(201).json({ message: 'Payslip request submitted successfully for approval!' });
    } catch (error) {
        console.error('[PAYSLIP SUBMIT ERROR]', error);
        res.status(500).json({ error: 'An error occurred on the server.' });
    }
});

app.post('/api/submit', authenticateToken, async (req, res) => {
    const { taskName, employeeName, employeeId, uploadDoc, taskStatus } = req.body;
    if (req.user.empId !== employeeId.toUpperCase()) {
        return res.status(403).json({ error: 'Forbidden: You can only submit work for yourself.' });
    }
    if (!taskName || !employeeName || !employeeId || !uploadDoc || !taskStatus) {
        return res.status(400).json({ error: "Missing required fields." });
    }
    try {
        const query = `INSERT INTO work_submissions (task_name, employee_name, employee_id, document_filename, status) VALUES ($1, $2, $3, $4, $5) RETURNING id`;
        const values = [taskName, employeeName, employeeId.toUpperCase(), uploadDoc, taskStatus];
        await pool.query(query, values);
        res.status(201).json({ message: 'Work submitted successfully!' });
    } catch (error) {
        console.error('[WORK SUBMIT ERROR]', error);
        res.status(500).json({ error: 'An error occurred on the server.' });
    }
});

// --- TASK (TO-DO LIST) ENDPOINTS ---

app.post('/api/tasks', authenticateToken, async (req, res) => {
    const { description } = req.body;
    if (!description) return res.status(400).json({ message: 'Task description required.' });
    try {
        const empId = req.user.empId;
        const result = await pool.query(
            'INSERT INTO tasks (employee_id, description) VALUES ($1, $2) RETURNING *',
            [empId, description]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('[TASK CREATE ERROR]', err);
        res.status(500).json({ message: 'Server error creating task.' });
    }
});

app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        const empId = req.user.empId;
        const { rows } = await pool.query(
            'SELECT * FROM tasks WHERE employee_id = $1 ORDER BY created_on DESC',
            [empId]
        );
        res.json(rows);
    } catch (err) {
        console.error('[TASK FETCH ERROR]', err);
        res.status(500).json({ message: 'Server error fetching tasks.' });
    }
});

app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
    try {
        const empId = req.user.empId;
        const { id } = req.params;
        const result = await pool.query(
            'DELETE FROM tasks WHERE id = $1 AND employee_id = $2 RETURNING *',
            [id, empId]
        );
        if (result.rowCount === 0) return res.status(404).json({ message: 'Task not found or you do not have permission to delete it.' });
        res.json({ message: 'Task deleted.' });
    } catch (err) {
        console.error('[TASK DELETE ERROR]', err);
        res.status(500).json({ message: 'Server error deleting task.' });
    }
});

// GET endpoint to fetch banking details for the logged-in user
app.get('/api/banking-details', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT * FROM banking_details WHERE employee_id = $1',
            [req.user.empId]
        );
        // Return the details if they exist, or an empty object if they don't
        res.json(rows[0] || {});
    } catch (err) {
        console.error('[BANKING GET ERROR]', err);
        res.status(500).json({ message: 'Server error fetching banking details.' });
    }
});

// POST endpoint to save or update banking details
app.post('/api/banking-details', authenticateToken, async (req, res) => {
    const { employee_id, bank_name, account_holder_name, account_number, ifsc_code, account_type } = req.body;

    // Security check: Ensure the user is only updating their own details
    if (req.user.empId !== employee_id) {
        return res.status(403).json({ message: 'Forbidden: You can only update your own banking details.' });
    }

    if (!bank_name || !account_holder_name || !account_number || !ifsc_code || !account_type) {
        return res.status(400).json({ message: 'All banking fields are required.' });
    }

    try {
        const query = `
            INSERT INTO banking_details (employee_id, bank_name, account_holder_name, account_number, ifsc_code, account_type)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (employee_id) 
            DO UPDATE SET
                bank_name = EXCLUDED.bank_name,
                account_holder_name = EXCLUDED.account_holder_name,
                account_number = EXCLUDED.account_number,
                ifsc_code = EXCLUDED.ifsc_code,
                account_type = EXCLUDED.account_type
            RETURNING *;
        `;
        const values = [employee_id, bank_name, account_holder_name, account_number, ifsc_code, account_type];
        await pool.query(query, values);
        res.status(200).json({ message: 'Banking details saved successfully!' });
    } catch (err) {
        console.error('[BANKING POST ERROR]', err);
        res.status(500).json({ message: 'An error occurred on the server while saving details.' });
    }
});

// --- NEW HELP DESK ENDPOINTS ---

// GET endpoint to fetch all tickets for the logged-in user
app.get('/api/helpdesk-tickets', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT * FROM help_desk_tickets WHERE employee_id = $1 ORDER BY submitted_on DESC',
            [req.user.empId]
        );
        res.json(rows);
    } catch (err) {
        console.error('[HELPDESK GET ERROR]', err);
        res.status(500).json({ message: 'Server error fetching help desk tickets.' });
    }
});

// POST endpoint to create a new help desk ticket
app.post('/api/helpdesk-tickets', authenticateToken, async (req, res) => {
    const { category, priority, subject, description } = req.body;
    
    if (!category || !priority || !subject || !description) {
        return res.status(400).json({ message: 'Category, priority, subject, and description are required.' });
    }

    try {
        // Fetch user details to ensure data integrity
        const userResult = await pool.query('SELECT username, email FROM users WHERE employee_id = $1', [req.user.empId]);
        if (userResult.rowCount === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }
        const { username, email } = userResult.rows[0];

        const query = `
            INSERT INTO help_desk_tickets (employee_id, employee_name, email, category, priority, subject, description)
            VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;
        `;
        const values = [req.user.empId, username, email, category, priority, subject, description];
        await pool.query(query, values);
        res.status(201).json({ message: 'Help desk ticket created successfully!' });
    } catch (err) {
        console.error('[HELPDESK POST ERROR]', err);
        res.status(500).json({ message: 'An error occurred on the server while creating the ticket.' });
    }
});


// --- Server Start ---
async function startServer() {
    pool = await initializeDatabase();
    app.listen(PORT, () => {
        console.log(`\n✅ Server is running on http://localhost:${PORT}`);
        console.log(`🔗 Access the HRMS at http://localhost:${PORT}/login`);
    });
}

startServer();