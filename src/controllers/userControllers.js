const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const { Resend } = require('resend');


const resend = new Resend(process.env.RESEND_API_KEY);


// // Email configuration
// const transporter = nodemailer.createTransport({
//     service: 'gmail',
//     auth: {
//         user: process.env.EMAIL_USER,
//         pass: process.env.EMAIL_PASSWORD
//     },
//     debug: true, // Add this for debugging
//     logger: true // Add this for debugging
// });

// // Test the connection
// transporter.verify(function(error, success) {
//     if (error) {
//         console.log('Email server error:', error);
//     } else {
//         console.log('Email server is ready');
//     }
// });

// Get all users (Admin only)
const getAllUsers = async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.status(200).json(users);
    } catch (err) {
        res.status(500).json({ message: "Error fetching users" });
    }
};

// Get single user
const getUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json(user);
    } catch (err) {
        res.status(500).json({ message: "Error fetching user" });
    }
};

// Update user
const updateUser = async (req, res) => {
    try {
        const { firstName, lastName, email, role } = req.body;
        const user = await User.findById(req.params.id);

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Only admin can update roles
        if (role && req.user.role !== 'admin') {
            return res.status(403).json({ message: "Not authorized to update role" });
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            { firstName, lastName, email, role },
            { new: true }
        ).select('-password');

        res.status(200).json(updatedUser);
    } catch (err) {
        res.status(500).json({ message: "Error updating user" });
    }
};

// Delete user (Admin only)
const deleteUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        await User.findByIdAndDelete(req.params.id);
        res.status(200).json({ message: "User deleted successfully" });
    } catch (err) {
        res.status(500).json({ message: "Error deleting user" });
    }
};

// Request password reset
const requestPasswordReset = async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        const resetToken = crypto.randomBytes(32).toString('hex');
        user.passwordResetToken = crypto
            .createHash('sha256')
            .update(resetToken)
            .digest('hex');
        user.passwordResetExpires = Date.now() + 30 * 60 * 1000; // 30 minutes
        await user.save();

        const resetURL = `${process.env.USERS_BACKEND_URL}/reset-password/${resetToken}`;

        resend.emails.send({
            from: process.env.EMAIL_USER ,
            to: user.email,
            subject: 'Password Reset Request',
            html: `
                <p>You requested a password reset</p>
                <p>Click this <a href="${resetURL}">link</a> to set a new password.</p>
                <p>If you didn't request this, please ignore this email.</p>
                <p>This link is valid for 30 minutes.</p>
            `
          });
          console.log("hi")

        // const mailOptions = {
        //     from: process.env.EMAIL_USER,
        //     to: user.email,
        //     subject: 'Password Reset Request',
        //     html: `
        //         <p>You requested a password reset</p>
        //         <p>Click this <a href="${resetURL}">link</a> to set a new password.</p>
        //         <p>If you didn't request this, please ignore this email.</p>
        //         <p>This link is valid for 30 minutes.</p>
        //     `
        // };

        // await transporter.sendMail(mailOptions);
        res.status(200).json({ message: "Reset link sent to email" });
    } catch (err) {
        res.status(500).json({ message: "Error sending reset email" });
    }
};

// Reset password
const resetPassword = async (req, res) => {
    try {
        const hashedToken = crypto
            .createHash('sha256')
            .update(req.params.token)
            .digest('hex');

        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: "Token is invalid or has expired" });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        user.password = hashedPassword;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save();

        res.status(200).json({ message: "Password reset successful" });
    } catch (err) {
        res.status(500).json({ message: "Error resetting password" });
    }
};

module.exports = {
    getAllUsers,
    getUser,
    updateUser,
    deleteUser,
    requestPasswordReset,
    resetPassword
};
