require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const ipRangeCheck = require("ip-range-check");
const nodemailer = require("nodemailer");
// 💡 REQUIRED FOR FILE HANDLING & SECURITY
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcryptjs'); // For password hashing

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'mysupersecret';

app.set('trust proxy', true);

// ------------------------------------------------
// 💡 Multer Configuration for Photo Uploads
// ------------------------------------------------
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Files are saved here (must exist!)
        cb(null, 'public/uploads/');
    },
    filename: (req, file, cb) => {
        // Use USN + timestamp for a unique name
        // IMPORTANT: We trust req.body.usn exists here due to form validation
        const usn = req.body.usn ? req.body.usn.toUpperCase() : 'NO_USN';
        const ext = path.extname(file.originalname);
        cb(null, usn + '-' + Date.now() + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            // Note: This error is caught in the route handler's try/catch
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});
// ------------------------------------------------

mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/attendanceApp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Schemas
const userSchema = new mongoose.Schema({
    name: String,
    usn: { type: String, unique: true },
    password: String, // Stores the HASHED password
    role: { type: String, default: 'student' },
    deviceId: String,
    email: String,
    // 💡 NEW FIELD: Stores the relative path to the student's photo
    photoPath: { type: String, default: null },
    class: { type: String, required: true }
});


const attendanceSchema = new mongoose.Schema({
    usn: String,
    date: { 
        type: String, 
        default: () => {
            const today = new Date();
            return today.toISOString().split('T')[0]; // yyyy-mm-dd format
        }
    },
    status: { type: String, enum: ['present', 'absent', 'pending'], default: 'pending' },
    markedBy: { type: String, default: 'student' },
    approvalRequested: { type: Boolean, default: false },
    approvedByAdmin: { type: Boolean, default: false }
});


// ... [Campus and IP Schema definitions remain the same] ...
const campusSchema = new mongoose.Schema({ latitude: Number, longitude: Number, radius: Number });
const ipSchema = new mongoose.Schema({ address: String });
const IPWhitelist = mongoose.model('IPWhitelist', ipSchema);
const Campus = mongoose.model('Campus', campusSchema);
const Approval = mongoose.model("Approval", new mongoose.Schema({
    studentName: String, studentId: String, date: { type: Date, default: Date.now },
    status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" }
}));

const User = mongoose.model('User', userSchema);
const Attendance = mongoose.model('Attendance', attendanceSchema);


app.use(cors());
// Multer handles multipart/form-data. We still need bodyParser for non-file JSON routes.
app.use(bodyParser.json()); 
app.use(express.static('public')); // Serves static files, including /uploads/

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'shashistudy2125@gmail.com',
        pass: process.env.EMAIL_PASS || 'xweh opxh bcgi yhjr'
    }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// ------------------------------------------------
// 💡 MODIFIED: Register Route (File Upload & Password Hashing)
// ------------------------------------------------
app.post('/api/register', upload.single('photo'), async (req, res) => {
    const { name, usn, password, role, email,class: studentClass } = req.body;
    
    // Check if Multer successfully handled the file
    if (!req.file) {
        return res.status(400).json({ error: "Photo/Selfie is required for registration." });
    }

    if (!name || !usn || !password || !email || !studentClass ) {
        // Delete the saved file if other required fields are missing
        fs.unlink(req.file.path, () => {});
        return res.status(400).json({ error: "All fields required" });
    }

    try {
        const existing = await User.findOne({ usn });
        if (existing) {
            // Delete the saved file if USN already exists
            fs.unlink(req.file.path, () => {});
            return res.status(400).json({ error: "USN already registered" });
        }

        // 🚨 SECURITY: Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Get path relative to the 'public' folder for URL access
        const photoPath = req.file.path.replace(/\\/g, '/').replace('public/', '');
        
        const newUser = new User({
            name,
            usn,
            password: hashedPassword, // Store the HASH
            role: role || 'student',
            email,
            class: studentClass,
            photoPath // Store the file path
        });
        
        await newUser.save();
        res.json({ message: "✅ Registration successful, please login", photoPath });
    } catch (err) {
        console.error(err);
        // Clean up the file if a database error occurs
        if(req.file) fs.unlink(req.file.path, () => {});
        res.status(500).json({ error: "Server error during registration" });
    }
});


// ------------------------------------------------
// 💡 MODIFIED: Login Route (Password Comparison)
// ------------------------------------------------
app.post('/api/login', async (req, res) => {
    const { usn, password, deviceId } = req.body;
    if (!usn || !password) return res.status(400).json({ error: 'USN and password required' });

    try {
        const user = await User.findOne({ usn });
        
        // 🚨 SECURITY: Compare the plaintext password with the stored hash
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'Invalid USN or password' });
        }

        if (user.role !== 'admin') {
            if (!deviceId) return res.status(400).json({ error: 'Device ID required for students' });

            const otherUser = await User.findOne({ usn: { $ne: usn }, deviceId });
            if (otherUser) return res.status(403).json({ error: `Device registered to another student (${otherUser.usn})` });

            if (!user.deviceId) { user.deviceId = deviceId; await user.save(); }
            else if (user.deviceId !== deviceId) return res.status(403).json({ error: 'This account can only be accessed from the registered device.' });
        }

        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// Auth middleware

function authMiddleware(req, res, next){
  const authHeader = req.headers['authorization'];
  if(!authHeader) return res.status(401).json({ error: 'No token' });

  const token = authHeader.split(' ')[1];
  if(!token) return res.status(401).json({ error: 'No token' });

  try{
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch(err){
    return res.status(403).json({ error: 'Invalid token' });
  }
}


// ------------------------------------------------
// 💡 MODIFIED: Current user endpoint (Includes photoPath)
// ------------------------------------------------
app.get('/api/me', authMiddleware, async (req, res) => {
    const me = await User.findById(req.user.id).lean();
    if (!me) return res.status(404).json({ error: 'User not found' });
    // Include photoPath in the response
    res.json({ name: me.name, usn: me.usn, role: me.role, photoPath: me.photoPath });
});

// GPS distance check (helper function)
function isWithinRadius(lat1, lon1, lat2, lon2, radiusMeters) {
    const toRad = (v) => (v * Math.PI)/180;
    const R = 6371e3;
    const φ1 = toRad(lat1), φ2 = toRad(lat2);
    const Δφ = toRad(lat2 - lat1), Δλ = toRad(lon2 - lon1);
    const a = Math.sin(Δφ/2)**2 + Math.cos(φ1)*Math.cos(φ2)*Math.sin(Δλ/2)**2;
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    const d = R * c;
    return d <= radiusMeters;
}

// Attendance marking
app.post('/api/attendance', authMiddleware, async (req, res) => {
    try {
        let clientIP = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket?.remoteAddress || req.ip || '';
        if (clientIP.includes('::ffff:')) { clientIP = clientIP.replace('::ffff:', ''); }

        const { latitude, longitude, status } = req.body;

        let withinAnyCampus = false;
        if (latitude && longitude) {
            const campuses = await Campus.find({});
            withinAnyCampus = campuses.some(c =>
                isWithinRadius(latitude, longitude, c.latitude, c.longitude, c.radius)
            );
        }

        if (!withinAnyCampus) {
            const whitelist = await IPWhitelist.find({});
            const allowedIPs = whitelist.map(ip => ip.address);
            const ipAllowed = allowedIPs.some(ip => ipRangeCheck(clientIP, ip));

            if (!ipAllowed) {
                return res.status(403).json({ error: '❌ Not inside campus or allowed IP', yourIP: clientIP });
            }
        }

        const me = await User.findById(req.user.id).lean();
        if (!me) return res.status(404).json({ error: 'User not found' });

        const today = new Date().toISOString().split('T')[0];
        const existing = await Attendance.findOne({ usn: me.usn, date: today });
        if (existing) return res.json({ message: 'Attendance already marked today' });

        await Attendance.create({
    usn: me.usn.toUpperCase(), // <-- force uppercase
    date: today,
    status,
    markedBy: 'student'
});


        res.json({ message: `✅ Attendance marked as ${status}`, ipUsed: clientIP });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});


// Admin today
app.get('/api/admin/today', authMiddleware, async (req,res)=>{
    const me = await User.findById(req.user.id).lean();
    if(!me || me.role!=='admin') return res.status(403).json({error:'Access denied'});

    const today = new Date().toISOString().split("T")[0];
    const list = await Attendance.find({ date: today, status: 'present' });
    const sortedUsns = list.map(x=>x.usn).sort((a,b)=>a.localeCompare(b,undefined,{numeric:true}));
    res.json({ total: sortedUsns.length, usns: sortedUsns });
});

// Admin reset
app.post('/api/admin/reset-all', authMiddleware, async (req,res)=>{
    const me = await User.findById(req.user.id).lean();
    if(!me || me.role!=='admin') return res.status(403).json({error:'Access denied'});
    try{
        await Attendance.deleteMany({});
        await User.updateMany({ role:'student' }, { $set:{ deviceId:null } });
        res.json({ message: '✅ All attendance records and student device IDs cleared.' });
    }catch(err){ console.error(err); res.status(500).json({error:'Server error during reset'}); }
});

// Admin send email
app.post('/api/admin/send-email', authMiddleware, async (req, res) => {
  try {
    const me = await User.findById(req.user.id).lean();
    if (!me || me.role !== 'admin')
      return res.status(403).json({ error: 'Access denied' });

    const { email } = req.body;
    if (!email)
      return res.status(400).json({ error: 'Email required' });

    const today = new Date().toISOString().split("T")[0];
    const list = await Attendance.find({ date: today, status: 'present' });
    const sortedUsns = list.map(x => x.usn).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    const total = sortedUsns.length;

    let rows = "";
    for (let i = 0; i < sortedUsns.length; i += 2) {
      rows += `<tr><td>${i + 1}. ${sortedUsns[i]}</td><td>${sortedUsns[i + 1] ? i + 2 + ". " + sortedUsns[i + 1] : ""}</td></tr>`;
    }

    const message = `
      <div style="font-family: Arial;padding:15px;background:#f9fafb;">
        <h2 style="text-align:center;">📘 Attendance Report</h2>
        <p><b>Date:</b> ${today}</p>
        <p><b>Total Present:</b> ${total}</p>
        <table style="border-collapse: collapse;width:80%;margin:auto;font-size:14px;">
          <thead><tr style="background:#2E86C1;color:white;"><th>USN ROW 1</th><th>USN ROW 2</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: `Today's Attendance - ${today}`,
      html: message,
    });

    res.json({ message: `✅ Attendance sent to ${email}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send email' });
  }
});


// --- Admin: add new campus location ---
app.post('/api/admin/campus-location', authMiddleware, async (req,res)=>{
    const me = await User.findById(req.user.id).lean();
    if(!me || me.role!=='admin') return res.status(403).json({error:'Access denied'});

    const { latitude, longitude, radius } = req.body;
    if(!latitude || !longitude || !radius) return res.status(400).json({error:'Latitude, longitude and radius required'});

    try {
        const campus = new Campus({ latitude, longitude, radius });
        await campus.save();
        res.json({ message:'✅ Campus location added' });
    } catch(err){ console.error(err); res.status(500).json({error:'Failed to save campus location'}); }
});

// --- Admin: get all campus locations ---
app.get('/api/admin/campus-locations', authMiddleware, async (req,res)=>{
    const me = await User.findById(req.user.id).lean();
    if(!me || me.role!=='admin') return res.status(403).json({error:'Access denied'});

    const locations = await Campus.find({});
    res.json(locations);
});

// --- Admin: delete a campus location ---
app.delete('/api/admin/campus-location/:id', authMiddleware, async (req, res) => {
    const me = await User.findById(req.user.id).lean();
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    try {
        const id = req.params.id;
        await Campus.findByIdAndDelete(id);
        res.json({ message: '✅ Campus location removed' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to remove campus location' });
    }
});

// Student requests approval
app.post('/api/request-approval', authMiddleware, async (req, res) => {
    const me = await User.findById(req.user.id).lean();
    if (!me || me.role !== 'student') return res.status(403).json({ error: 'Only students can request approval' });

    const today = new Date().toISOString().split("T")[0];

    const existing = await Attendance.findOne({ usn: me.usn, date: today });
    if (existing) return res.json({ message: 'Attendance already recorded today' });

    await Attendance.create({
        usn: me.usn,
        date: today,
        status: 'pending',
        approvalRequested: true
    });

    res.json({ message: 'Approval requested, wait for admin.' });
});

// Admin: get all pending approvals (with student details)
app.get('/api/admin/pending-approvals', authMiddleware, async (req, res) => {
    const me = await User.findById(req.user.id).lean();
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    const today = new Date().toISOString().split("T")[0];
    const requests = await Attendance.find({ date: today, status: 'pending', approvalRequested: true }).lean();

    const withStudentInfo = await Promise.all(requests.map(async (reqItem) => {
        const student = await User.findOne({ usn: reqItem.usn }).lean();
        return {
            ...reqItem,
            name: student ? student.name : "Unknown",
            usn: student ? student.usn : reqItem.usn
        };
    }));

    res.json(withStudentInfo);
});


// Admin: approve student
app.post('/api/admin/approve', authMiddleware, async (req, res) => {
    const me = await User.findById(req.user.id).lean();
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    const { id } = req.body;
    const updated = await Attendance.findByIdAndUpdate(id, {
        status: 'present',
        approvedByAdmin: true,
        markedBy: 'admin'
    }, { new: true });

    if (!updated) return res.status(404).json({ error: 'Request not found' });

    // Get student details and send email (logic remains the same)
    const student = await User.findOne({ usn: updated.usn }).lean();
    if (student && student.email) {
        try {
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: student.email,
                subject: "✅ Attendance Request Approved",
                html: `<p>Hello <b>${student.name}</b>,</p>
                      <p>Your attendance request for <b>${updated.date}</b> has been <span style="color:green;">Approved</span> ✅ by Admin.</p>`
            });
        } catch (err) {
            console.error("❌ Email error:", err);
        }
    }

    res.json({ message: '✅ Attendance approved and email sent' });
});


// Admin: reject student
app.post('/api/admin/reject', authMiddleware, async (req, res) => {
    const me = await User.findById(req.user.id).lean();
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    const { id } = req.body;
    const updated = await Attendance.findByIdAndUpdate(id, {
        status: 'absent',
        approvedByAdmin: false,
        markedBy: 'admin'
    }, { new: true });

    if (!updated) return res.status(404).json({ error: 'Request not found' });

    // Get student details and send email (logic remains the same)
    const student = await User.findOne({ usn: updated.usn }).lean();
    if (student && student.email) {
        try {
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: student.email,
                subject: "❌ Attendance Request Rejected",
                html: `<p>Hello <b>${student.name}</b>,</p>
                       <p>Your attendance request for <b>${updated.date}</b> has been
                       <span style="color:red;">Rejected</span> ❌ by Admin.</p>`
            });
        } catch (err) {
            console.error("❌ Email error:", err);
        }
    }

    res.json({ message: '❌ Attendance rejected and email sent' });
});

// Alias for frontend: /api/attendance/request-approval
app.post('/api/attendance/request-approval', authMiddleware, async (req, res) => {
    const me = await User.findById(req.user.id).lean();
    if (!me || me.role !== 'student') return res.status(403).json({ error: 'Only students can request approval' });

    const today = new Date().toISOString().split("T")[0];

    const existing = await Attendance.findOne({ usn: me.usn, date: today });
    if (existing) return res.json({ message: 'Attendance already recorded today' });

    await Attendance.create({ usn: me.usn, date: today, status: 'pending', approvalRequested: true });

    res.json({ message: 'Approval requested, wait for admin.' });
});


// ... [Remaining Approval and IP Whitelist routes remain the same] ...

app.get("/api/attendance/approvals", async (req, res) => {
    try {
        const approvals = await Approval.find({ status: "pending" });
        res.json(approvals);
    } catch (err) {
        res.status(500).json({ success: false, message: "Error fetching approvals" });
    }
});

app.post("/api/attendance/update-approval", async (req, res) => {
    try {
        const { id, status } = req.body;
        await Approval.findByIdAndUpdate(id, { status });

        res.json({ success: true, message: "Approval updated" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Error updating approval" });
    }
});

// Add new IP
app.post('/api/admin/allowed-ip', authMiddleware, async (req, res) => {
    const me = await User.findById(req.user.id).lean();
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    let { address } = req.body;
    if (!address) return res.status(400).json({ error: 'IP address required' });

    address = address.replace(/^::ffff:/, '').trim();

    try {
        const exists = await IPWhitelist.findOne({ address });
        if (exists) {
            return res.json({ message: '⚠️ This IP is already whitelisted' });
        }

        await IPWhitelist.create({ address });
        res.json({ message: `✅ IP ${address} added to whitelist` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error while adding IP' });
    }
});


// Get all IPs
app.get('/api/admin/allowed-ips', authMiddleware, async (req, res) => {
    const me = await User.findById(req.user.id).lean();
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    const ips = await IPWhitelist.find({});
    res.json(ips);
});

// Delete IP
app.delete('/api/admin/allowed-ip/:id', authMiddleware, async (req, res) => {
    const me = await User.findById(req.user.id).lean();
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    await IPWhitelist.findByIdAndDelete(req.params.id);
    res.json({ message: '✅ IP removed from whitelist' });
});
// ------------------------------------------------
// 💡 ADMIN FEATURE: Export Attendance Report to Excel (robust + debug)
// ------------------------------------------------
const ExcelJS = require('exceljs');

app.post('/api/admin/export-attendance', async (req, res) => {
  try {
    const { teacherName, className, date } = req.body;

    // 1️⃣ Fetch attendance records
    const records = await Attendance.find({ date }).lean();
    if (!records.length) {
      console.log(`No attendance records found for date: ${date}`);
      return res.status(404).json({ error: 'No attendance records found for this date' });
    }

    // 2️⃣ Extract USNs
    const usns = records.map(r => r.usn);

    // 3️⃣ Get student details for those USNs
    const students = await User.find({ usn: { $in: usns } }).lean();

    // 4️⃣ Create workbook
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Attendance Report');

    // 5️⃣ Define columns
    worksheet.columns = [
      { header: 'SL No', key: 'sl', width: 10 },
      { header: 'Student Name', key: 'name', width: 25 },
      { header: 'USN', key: 'usn', width: 20 },
      { header: 'Date', key: 'date', width: 15 },
      { header: 'Status', key: 'status', width: 15 },
      { header: 'Marked By', key: 'markedBy', width: 20 }
    ];

    // 6️⃣ Add header rows
    worksheet.insertRow(1, [`Attendance Report - ${className}`]);
    worksheet.mergeCells('A1:F1');
    worksheet.getCell('A1').font = { size: 16, bold: true };
    worksheet.getCell('A1').alignment = { horizontal: 'center' };

    worksheet.insertRow(2, [`Teacher: ${teacherName} | Date: ${date}`]);
    worksheet.mergeCells('A2:F2');
    worksheet.getCell('A2').alignment = { horizontal: 'center' };

    // 7️⃣ Add data
    records.forEach((rec, i) => {
      const student = students.find(
        s => s.usn && s.usn.toUpperCase() === rec.usn.toUpperCase()
      );
      worksheet.addRow({
        sl: i + 1,
        name: student ? student.name : 'Unknown',
        usn: rec.usn || '',
        date: rec.date || date,
        status: rec.status || '',
        markedBy: rec.markedBy || ''
      });
    });

    worksheet.getRow(3).font = { bold: true };
    worksheet.getRow(3).alignment = { horizontal: 'center' };

    // 8️⃣ Send file as response
    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      `attachment; filename=Attendance_${className}_${date}.xlsx`
    );

    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {
    console.error('Export error:', err);
    res.status(500).json({ error: 'Server error during export' });
  }
});

// 🌐 AUTO TRANSLATION API (Google Translate)
const translate = require('@vitalets/google-translate-api');

app.get('/api/translate', async (req, res) => {
  try {
    const { text, lang } = req.query;
    const result = await translate(text, { to: lang });
    res.json({ translatedText: result.text });
  } catch (error) {
    console.error('Translation error:', error);
    res.status(500).json({ error: 'Failed to translate text' });
  }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, ()=>console.log(`🚀 Server running on port ${PORT}`));
