const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const moment = require("moment"); // Install moment.js for easier date handling
require("dotenv").config();

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Define Schemas and Models
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  emiratesId: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  age: { type: Number },
  gender: { type: String, enum: ["Male", "Female"] },
  bloodType: { type: String },
  contactNumber: { type: String },
  parentNumber: { type: String },
  doctor: { type: mongoose.Schema.Types.ObjectId, ref: "Doctor" }, // Reference to the Doctor
});

const DoctorSchema = new mongoose.Schema({
  fullName: String,
  emiratesId: String,
  email: { type: String, unique: true },
  password: String,
  speciality: String,
});

const MessageSchema = new mongoose.Schema(
  {
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Doctor",
      required: true,
    },
    recipient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    content: {
      type: String,
      required: true,
    },
    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true } // Automatically adds createdAt and updatedAt
);

const MedicationSchema = new mongoose.Schema({
  name: { type: String, required: true },
  instructions: { type: String },
  dose: { type: String, required: true },
  image: { type: String }, // URL to the medication image
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  time: { type: String, required: true }, // e.g., "8:00 AM"
  quantity: { type: Number, required: true },
  description: { type: String },
  doctor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Doctor",
    required: true,
  },
  status: {
    type: String,
    enum: ["missed", "taken", "pending"],
    default: "pending",
  },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
});

const medicalHistorySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  date: { type: Date, required: true },
  heartRate: { type: String, required: true },
  bloodPressure: { type: String, required: true },
});

const User = mongoose.model("User", UserSchema);
const MedicalHistory = mongoose.model("MedicalHistory", medicalHistorySchema);
const Doctor = mongoose.model("Doctor", DoctorSchema);
const Medication = mongoose.model("Medication", MedicationSchema);
const Message = mongoose.model("Message", MessageSchema);

// Middleware to validate JWT
const authenticateToken = (req, res, next) => {
  // console.log(req.headers.authorization);
  const token = req.headers.authorization.split(" ")[1];
  // console.log(token);
  if (!token) return res.status(401).send("Access Denied");

  try {
    const verified = jwt.verify(token, "abullah");
    req.user = verified;
    next();
  } catch (err) {
    console.log(err);
    res.status(400).send("Invalid Token");
  }
};

app.get("/medical-history", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id; // Assume the user ID is available from a JWT token or session

    // Fetch medical history for the logged-in user, sorted by date in descending order
    const history = await MedicalHistory.find({ user: userId })
      .sort({ date: -1 }) // Sort by date: latest first
      .select("date heartRate bloodPressure"); // Only select the necessary fields

    res.json(history); // Send the history data as JSON
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ message: "An error occurred while fetching medical history." });
  }
});

// Routes
// Sign Up User
app.post("/signup/user", async (req, res) => {
  const { fullname, eid, email, password } = req.body;
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const user = new User({
    fullName: fullname,
    eid,
    email,
    password: hashedPassword,
  });
  try {
    const savedUser = await user.save();
    res.json(savedUser);
  } catch (err) {
    res.status(400).send(err);
  }
});

// Sign Up Doctor
app.post("/signup/doctor", async (req, res) => {
  const { fullName, emiratesId, email, password, speciality } = req.body;
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const doctor = new Doctor({
    fullName: `Dr. ${fullName}`,
    emiratesId,
    email,
    password: hashedPassword,
    speciality,
  });
  try {
    const savedDoctor = await doctor.save();
    res.json(savedDoctor);
  } catch (err) {
    res.status(400).send(err);
  }
});

const createDoctor = async () => {
  try {
    const doctor = new Doctor({
      fullName: "Dr. Jane Doe",
      emiratesId: "123-456-789",
      email: "jane.doe@example.com",
      password: "hashed_password", // Hash this password with bcrypt in real cases
      speciality: "General Physician",
    });

    const savedDoctor = await doctor.save();
    console.log("Doctor created:", savedDoctor);
    mongoose.connection.close();
  } catch (err) {
    console.error("Error creating doctor:", err);
    mongoose.connection.close();
  }
};
const createMedications = async () => {
  try {
    const doctorId = "6744cb613469501aedaaea33"; // Replace with the actual doctor ID from your database
    const userId = "67449e931d49f680b15645a0"; // Replace with an actual user ID

    const medications = [
      {
        name: "Paracetamol",
        instructions: "Take after meals",
        dose: "500mg",
        image: "https://example.com/image.png",
        startDate: new Date("2024-11-01"),
        endDate: new Date("2024-11-07"),
        time: "8:00 AM",
        quantity: 14,
        description: "For fever and pain relief",
        doctor: doctorId,
        user: userId,
      },
      {
        name: "Ibuprofen",
        instructions: "Take with water",
        dose: "200mg",
        image: "https://example.com/image2.png",
        startDate: new Date("2024-11-01"),
        endDate: new Date("2024-11-10"),
        time: "6:00 PM",
        quantity: 20,
        description: "For pain and inflammation",
        doctor: doctorId,
        user: userId,
      },
    ];

    const savedMedications = await Medication.insertMany(medications);
    console.log("Medications created:", savedMedications);
    mongoose.connection.close();
  } catch (err) {
    console.error("Error creating medications:", err);
    mongoose.connection.close();
  }
};

app.patch("/user/update", authenticateToken, async (req, res) => {
  try {
    const { userId, age, gender, bloodType, contactNumber, parentNumber } =
      req.body;

    // Check if the logged-in user is a doctor
    const doctorId = req.user.id; // Assuming the doctor ID comes from the JWT token
    const doctor = await Doctor.findById(doctorId);

    if (!doctor) {
      return res
        .status(403)
        .json({ message: "Only a doctor can perform this action" });
    }

    // Update the user's details and assign the doctor
    const user = await User.findByIdAndUpdate(
      userId,
      {
        age,
        gender,
        bloodType,
        contactNumber,
        parentNumber,
        doctor: doctorId,
      },
      { new: true } // Return the updated document
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "User details updated successfully",
      user,
    });
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ message: "An error occurred while updating user details" });
  }
});

// Authenticate User or Doctor
app.post("/login", async (req, res) => {
  const { email, password, role } = req.body; // role: 'user' or 'doctor'

  const Model = role === "doctor" ? Doctor : User;
  const account = await Model.findOne({ email });

  if (!account) return res.status(400).send("Account not found");

  const validPassword = await bcrypt.compare(password, account.password);
  if (!validPassword) return res.status(400).send("Invalid password");

  const token = jwt.sign({ id: account._id, role }, "abullah");
  res.json({ token, user: account });
});

// Assign Doctor to User
app.post("/assign-doctor", authenticateToken, async (req, res) => {
  const { doctorId } = req.body;

  if (req.user.role !== "user")
    return res.status(403).send("Access restricted to users only");

  try {
    const user = await User.findById(req.user.id);
    const doctor = await Doctor.findById(doctorId);

    if (!doctor) return res.status(404).send("Doctor not found");

    user.doctor = doctor._id;
    await user.save();

    res.json(user);
  } catch (err) {
    res.status(400).send(err);
  }
});

app.get("/medications/notifications", authenticateToken, async (req, res) => {
  try {
    const today = moment().startOf("day"); // Get today's date

    // Find medications that are scheduled for today
    const medications = await Medication.find({
      user: req.user.id,
      startDate: { $lte: today.toDate() }, // Medication starts on or before today
      endDate: { $gte: today.toDate() }, // Medication ends on or after today
    })
      .select("name time instructions image status") // Select required fields
      .populate("doctor", "fullName -_id"); // Populate doctor info (optional)

    // If no medications are found, send an empty array
    if (!medications.length) {
      return res.json([]);
    }

    // Process medications into the required format
    const notifications = medications.map((medication) => ({
      id: medication._id.toString(),
      name: medication.name,
      time: medication.time,
      instructions: medication.instructions || "No specific instructions",
      image: medication.image || "https://placehold.jp/150x150.png", // Default image if none is provided
      status: medication.status, // Pending, taken, or missed
    }));

    // Return notifications response
    res.json(notifications);
  } catch (err) {
    console.error("Error fetching notifications:", err);
    res
      .status(500)
      .send({ message: "An error occurred while fetching notifications." });
  }
});
app.get("/medications/doctor", authenticateToken, async (req, res) => {
  try {
    const doctorId = req.user.id;

    // Fetch medications prescribed by the logged-in doctor
    const medications = await Medication.find({ doctor: doctorId }).populate(
      "user",
      "name email"
    );

    if (!medications || medications.length === 0) {
      return res
        .status(404)
        .json({ message: "No medications found for this doctor." });
    }

    return res.status(200).json(medications);
  } catch (error) {
    console.error("Error fetching medications:", error);
    return res.status(500).json({ message: "Server error, please try again." });
  }
});
// Get User's Physician
app.get("/user/physician", authenticateToken, async (req, res) => {
  if (req.user.role !== "user")
    return res.status(403).send("Access restricted to users only");

  try {
    const user = await User.findById(req.user.id).populate(
      "doctor",
      "-password"
    );
    if (!user || !user.doctor)
      return res.status(404).send("No physician assigned");

    res.json(user.doctor);
  } catch (err) {
    res.status(400).send(err);
  }
});

app.post("/medications", authenticateToken, async (req, res) => {
  const {
    name,
    instructions,
    dose,
    image,
    startDate,
    endDate,
    time,
    quantity,
    description,
    userId,
  } = req.body;
  console.log(req.body);
  const doctorId = req.user.id;
  console.log(doctorId);
  if (req.user.role !== "doctor") {
    return res.status(403).send("Only doctors can prescribe medications.");
  }

  try {
    const doctor = await Doctor.findById(doctorId);
    const user = await User.findById(userId);

    if (!doctor || !user) {
      return res.status(404).send("Doctor or user not found.");
    }

    const medication = new Medication({
      name,
      instructions,
      dose,
      image,
      startDate,
      endDate,
      time,
      quantity,
      description,
      doctor: doctorId,
      user: userId,
    });

    const savedMedication = await medication.save();
    res.json(savedMedication);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.get("/doctor-profile", authenticateToken, async (req, res) => {
  try {
    // Fetch the doctor profile based on the authenticated doctor's ID
    const doctor = await Doctor.findById(req.user.id).select("-password -__v"); // Exclude sensitive data like password

    if (!doctor) {
      return res.status(404).send("Doctor profile not found.");
    }

    res.json(doctor);
  } catch (err) {
    console.log(err);
    res
      .status(500)
      .send("An error occurred while fetching the doctor profile.");
  }
});

app.get("/doctor/patients", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "doctor") {
      return res.status(403).send("Access restricted to doctors only");
    }

    // Find all users associated with the logged-in doctor's ID
    const users = await User.find({ doctor: req.user.id }).populate(
      "doctor",
      "fullName email speciality -_id" // Optional: exclude sensitive data
    );

    if (!users || users.length === 0) {
      return res.status(404).send("No users found for this doctor.");
    }

    res.json(users);
  } catch (err) {
    console.error("Error fetching users treated by doctor:", err);
    res
      .status(500)
      .send({ message: "An error occurred while fetching users." });
  }
});

// Get medications for a user to be taken today
app.get("/medications/today", authenticateToken, async (req, res) => {
  if (req.user.role !== "user") {
    return res.status(403).send("Access restricted to users.");
  }

  try {
    const today = moment().startOf("day"); // Get today's date
    const tomorrow = moment(today).add(1, "day"); // End of today's day

    const medications = await Medication.find({
      user: req.user.id,
      startDate: { $lte: today.toDate() }, // Medication starts on or before today
      endDate: { $gte: today.toDate() }, // Medication ends on or after today
    })
      .populate("doctor", "fullName email speciality -_id") // Include doctor details
      .select("-__v"); // Exclude MongoDB version key

    if (!medications.length) {
      return res.status(404).send("No medications to be taken today.");
    }

    res.json(medications);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.get("/medications/today-status", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const medicines = await Medication.find({
      user: userId,
      startDate: { $lte: today },
      endDate: { $gte: today },
    });

    const result = {
      taken: medicines.filter((med) => med.status === "taken"),
      missed: medicines.filter((med) => med.status === "missed"),
      pending: medicines.filter((med) => med.status === "pending"),
    };

    res.json(result);
  } catch (err) {
    console.error("Error fetching medications with status:", err);
    res
      .status(500)
      .send({ message: "An error occurred while fetching medications." });
  }
});

app.patch("/medications/:id/status", authenticateToken, async (req, res) => {
  try {
    const medicationId = req.params.id;
    const { status } = req.body; // Expected values: 'taken', 'missed'

    if (!["taken", "missed"].includes(status)) {
      return res.status(400).send({ message: "Invalid status value." });
    }

    const medication = await Medication.findById(medicationId);

    if (!medication) {
      return res.status(404).send({ message: "Medication not found." });
    }

    if (medication.user.toString() !== req.user.id) {
      return res
        .status(403)
        .send({ message: "Unauthorized to update this medication." });
    }

    medication.status = status;
    await medication.save();

    res.json({ message: "Medication status updated.", medication });
  } catch (err) {
    console.error("Error updating medication status:", err);
    res
      .status(500)
      .send({ message: "An error occurred while updating medication status." });
  }
});

app.get("/medications/:id", authenticateToken, async (req, res) => {
  const medicationId = req.params.id;

  try {
    // Fetch medication by ID
    const medication = await Medication.findById(medicationId)
      .populate("doctor", "fullName email speciality")
      .populate("user", "fullName email");

    if (!medication) {
      return res.status(404).send({ message: "Medication not found." });
    }

    // Return medication data
    res.json(medication);
  } catch (err) {
    console.error("Error fetching medication by ID:", err);
    res
      .status(500)
      .send({ message: "An error occurred while fetching the medication." });
  }
});
// Get all medications for a user
app.get("/medications", authenticateToken, async (req, res) => {
  // if (req.user.role !== "user") {
  //   return res.status(403).send("Access restricted to users.");
  // }

  try {
    const medications = await Medication.find({ user: req.user.id })
      .populate("doctor", "fullName email speciality -_id") // Include doctor details
      .select("-__v"); // Exclude MongoDB version key

    if (!medications.length) {
      return res.status(404).send("No medications found for this user.");
    }

    res.json(medications);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Get patient profile using token
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    // Fetch the user profile based on the authenticated user's ID
    const user = await User.findById(req.user.id).select("-password -__v"); // Exclude sensitive data like password
    if (!user) {
      return res.status(404).send("User profile not found.");
    }

    res.json(user);
  } catch (err) {
    console.log(err);
    res.status(500).send("An error occurred while fetching the profile.");
  }
});

app.get("/users-without-doctor", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "doctor") {
      return res.status(403).send("Access restricted to doctors only");
    }

    // Find all users where the doctor field is null or undefined
    const usersWithoutDoctor = await User.find({
      doctor: { $exists: false },
    }).select(
      "fullName email emiratesId _id" // Select only necessary fields
    );

    if (!usersWithoutDoctor.length) {
      return res.status(404).send("No users found without a doctor.");
    }

    res.json(usersWithoutDoctor);
  } catch (err) {
    console.error("Error fetching users without doctor:", err);
    res
      .status(500)
      .send({ message: "An error occurred while fetching users." });
  }
});

app.get("/users/doctor", authenticateToken, async (req, res) => {
  try {
    // Fetch the user data along with their assigned doctor
    const user = await User.findById(req.user.id).populate(
      "doctor",
      "fullName email speciality -_id"
    );

    if (!user) {
      return res.status(404).send("User not found.");
    }

    if (!user.doctor) {
      return res.status(404).send("Doctor not assigned to this user.");
    }

    res.json({
      doctor: user.doctor,
    });
  } catch (err) {
    res.status(500).send("An error occurred while fetching the doctor.");
  }
});

app.get("/", (req, res) => {
  res.json("success");
});

async function createUsers() {
  const doctorId = "67462192202fd5391c966fad";

  // Create an array of users
  const users = [
    {
      fullName: "John Doe",
      emiratesId: "123456789",
      email: "john.doe@example.com",
      password: "password123", // Ensure to hash the password before storing in production
      doctor: doctorId,
    },
    {
      fullName: "Jane Smith",
      emiratesId: "987654321",
      email: "jane.smith@example.com",
      password: "password123",
      doctor: doctorId,
    },
    {
      fullName: "Ali Ahmed",
      emiratesId: "192837465",
      email: "ali.ahmed@example.com",
      password: "password123",
      doctor: doctorId,
    },
    {
      fullName: "Sara Khan",
      emiratesId: "564738291",
      email: "sara.khan@example.com",
      password: "password123",
      doctor: doctorId,
    },
    {
      fullName: "Ravi Patel",
      emiratesId: "384756920",
      email: "ravi.patel@example.com",
      password: "password123",
      doctor: doctorId,
    },
  ];

  try {
    // Ensure mongoose is connected to the database before running the following code.
    // await mongoose.connect("mongodb://localhost:27017/yourDBName", { useNewUrlParser: true, useUnifiedTopology: true });

    // Insert the users into the database
    await User.insertMany(users);
    console.log("Users created successfully!");
  } catch (err) {
    console.error("Error creating users:", err);
  } finally {
    // Optionally, you can disconnect from the database after the operation.
    // mongoose.disconnect();
  }
}

async function createUsersWithHashedPasswords() {
  const users = [
    {
      fullName: "Chris Brown",
      emiratesId: "142536789",
      email: "chris.brown@example.com",
      password: "password123",
    },
    {
      fullName: "Emma Watson",
      emiratesId: "987123456",
      email: "emma.watson@example.com",
      password: "password123",
    },
    {
      fullName: "Liam Neeson",
      emiratesId: "123654789",
      email: "liam.neeson@example.com",
      password: "password123",
    },
    {
      fullName: "Sophia Loren",
      emiratesId: "789456123",
      email: "sophia.loren@example.com",
      password: "password123",
    },
    {
      fullName: "Ethan Hunt",
      emiratesId: "456789123",
      email: "ethan.hunt@example.com",
      password: "password123",
    },
  ];
  try {
    // Ensure mongoose is connected to the database before running this code.
    // await mongoose.connect("mongodb://localhost:27017/yourDBName", { useNewUrlParser: true, useUnifiedTopology: true });

    // Hash passwords for each user
    const salt = await bcrypt.genSalt(10);
    const usersWithHashedPasswords = await Promise.all(
      users.map(async (user) => {
        const hashedPassword = await bcrypt.hash(user?.password, salt);
        return { ...user, password: hashedPassword }; // Replace the plain password with the hashed one
      })
    );

    // Insert users into the database
    await User.insertMany(usersWithHashedPasswords);
    console.log("Users with hashed passwords created successfully!");
  } catch (err) {
    console.error("Error creating users with hashed passwords:", err);
  } finally {
    // Optionally, you can disconnect from the database after the operation.
    // mongoose.disconnect();
  }
}

const seedMessages = async () => {
  try {
    // Find the doctor and user (using the provided IDs)
    const doctor = await Doctor.findById("67462192202fd5391c966fad");
    const user = await User.findById("67449e931d49f680b15645a0");

    if (!doctor || !user) {
      console.log("Doctor or User not found");
      return;
    }

    // Create 5 sample messages
    const messages = [
      {
        sender: doctor._id,
        recipient: user._id,
        content: "Hello! How are you feeling today?",
      },
      {
        sender: doctor._id,
        recipient: user._id,
        content: "Don't forget to take your medication today.",
      },
      {
        sender: doctor._id,
        recipient: user._id,
        content: "I reviewed your test results, let's discuss them soon.",
      },
      {
        sender: doctor._id,
        recipient: user._id,
        content: "Please book an appointment for your next check-up.",
      },
      {
        sender: doctor._id,
        recipient: user._id,
        content: "If you have any questions, feel free to message me anytime.",
      },
    ];

    // Insert the messages into the database
    await Message.insertMany(messages);
    console.log("Messages seeded successfully");
  } catch (error) {
    console.error("Error seeding messages:", error);
  }
};

const seedMedications = async () => {
  const doctorId = "674630ec5945a9fe52bb1495";
  const userIds = [
    "67462bf72f5dba4e0b764e72",
    "67462bf72f5dba4e0b764e73",
    "67462bf72f5dba4e0b764e74",
    "67462bf72f5dba4e0b764e75",
    "674630ec5945a9fe52bb1495",
  ];
  try {
    const medications = [
      {
        name: "Paracetamol",
        instructions: "Take 1 tablet every 6 hours for pain relief.",
        dose: "500mg",
        image: "https://example.com/paracetamol.jpg", // Replace with actual image URL
        startDate: new Date("2024-11-25"),
        endDate: new Date("2024-12-25"),
        time: "8:00 AM",
        quantity: 30, // Number of tablets
        description: "Pain reliever",
        doctor: doctorId,
        user: userIds[0], // Assign to user 1
      },
      {
        name: "Ibuprofen",
        instructions: "Take 1 tablet every 8 hours for inflammation.",
        dose: "200mg",
        image: "https://example.com/ibuprofen.jpg", // Replace with actual image URL
        startDate: new Date("2024-11-25"),
        endDate: new Date("2024-12-10"),
        time: "12:00 PM",
        quantity: 15,
        description: "Anti-inflammatory drug",
        doctor: doctorId,
        user: userIds[1], // Assign to user 2
      },
      {
        name: "Amoxicillin",
        instructions: "Take 1 tablet every 12 hours for 7 days.",
        dose: "500mg",
        image: "https://example.com/amoxicillin.jpg", // Replace with actual image URL
        startDate: new Date("2024-11-20"),
        endDate: new Date("2024-11-27"),
        time: "9:00 AM",
        quantity: 14,
        description: "Antibiotic for infections",
        doctor: doctorId,
        user: userIds[2], // Assign to user 3
      },
      {
        name: "Cetirizine",
        instructions: "Take 1 tablet before bedtime for allergy relief.",
        dose: "10mg",
        image: "https://example.com/cetirizine.jpg", // Replace with actual image URL
        startDate: new Date("2024-11-15"),
        endDate: new Date("2024-12-15"),
        time: "10:00 PM",
        quantity: 30,
        description: "Antihistamine for allergies",
        doctor: doctorId,
        user: userIds[3], // Assign to user 4
      },
      {
        name: "Multivitamin",
        instructions: "Take 1 tablet daily with food.",
        dose: "1 tablet",
        image: "https://example.com/multivitamin.jpg", // Replace with actual image URL
        startDate: new Date("2024-11-01"),
        endDate: new Date("2024-12-01"),
        time: "7:00 AM",
        quantity: 30,
        description: "Vitamin supplement",
        doctor: doctorId,
        user: userIds[4], // Assign to user 5
      },
    ];

    // Insert the medications into the database
    await Medication.insertMany(medications);
    console.log("Medications seeded successfully!");
  } catch (err) {
    console.error("Error seeding medications:", err);
  }
};

app.get("/messages/user", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res.status(403).send("Access restricted to patients only.");
    }

    const messages = await Message.find({ recipient: req.user.id })
      .populate("sender", "fullName email")
      .populate("recipient", "fullName email");

    if (!messages || messages.length === 0) {
      return res.status(404).send("No messages found for this user.");
    }

    res.json(messages);
  } catch (err) {
    console.error("Error fetching messages for user:", err);
    res
      .status(500)
      .send({ message: "An error occurred while fetching messages." });
  }
});

app.get("/notifications/doctor", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "doctor") {
      return res.status(403).send("Access restricted to doctors only.");
    }

    // Find all medications prescribed by the logged-in doctor
    const medications = await Medication.find({ doctor: req.user.id })
      .populate("user", "fullName email") // Populate user details (patients)
      .populate("doctor", "fullName email"); // Populate doctor details

    if (!medications || medications.length === 0) {
      return res.status(404).send("No medications found for this doctor.");
    }

    // Separate medications into missed and taken
    const missedMedications = [];
    const takenMedications = [];

    medications.forEach((medication) => {
      const now = moment();
      const medicationTime = moment(medication.time, "HH:mm"); // Assuming time is in "HH:mm" format

      // Check if medication was taken or missed
      if (medicationTime.isBefore(now)) {
        // Medication should have been taken but it's past the time
        if (!medication.status || medication.status !== "taken") {
          missedMedications.push(medication);
        }
      } else {
        // Medication is scheduled in the future
        if (medication.status === "taken") {
          takenMedications.push(medication);
        }
      }
    });

    res.json({
      missed: missedMedications,
      taken: takenMedications,
    });
  } catch (err) {
    console.error("Error fetching medication notifications:", err);
    res
      .status(500)
      .send({ message: "An error occurred while fetching notifications." });
  }
});

app.post("/messages", authenticateToken, async (req, res) => {
  const { recipientId, content } = req.body;

  // Ensure only doctors can send messages
  if (req.user.role !== "doctor") {
    return res.status(403).send("Access restricted to doctors only.");
  }

  try {
    // Create a new message
    const newMessage = new Message({
      sender: req.user.id, // ID of the logged-in doctor
      recipient: recipientId,
      content,
    });

    // Save the message to the database
    const savedMessage = await newMessage.save();

    res.status(201).json(savedMessage);
  } catch (err) {
    console.error("Error storing message:", err);
    res
      .status(500)
      .send({ message: "An error occurred while saving the message." });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
