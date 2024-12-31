const express = require("express");
const verifyToken = require("../middlewares/authMiddleware");

const authorizeRoles = require("../middlewares/roleMiddleware");

const {
    getAllUsers,
    getUser,
    updateUser,
    deleteUser,
    requestPasswordReset,
    resetPassword
} = require("../controllers/userControllers");

const router = express.Router();

//admin
router.get("/admin",verifyToken,authorizeRoles("admin"), (req,res)=>{
    res.json({message:"Welcome Admin"});
}); 
//admin + manager
router.get("/manager",verifyToken,authorizeRoles("admin","manager"),(req,res)=>{
    res.json({message:"Welcome Manager"});
}); 
//all
router.get("/user",verifyToken,authorizeRoles("admin","manager","user"),(req,res)=>{
    res.json({message:"Welcome User"});
}); 

// Protected routes
router.get("/", verifyToken, authorizeRoles("admin"), getAllUsers);
router.get("/:id", verifyToken, authorizeRoles("admin", "manager"), getUser);
router.put("/:id", verifyToken, authorizeRoles("admin", "manager"), updateUser);
router.delete("/:id", verifyToken, authorizeRoles("admin"), deleteUser);

// public routes
// Password reset  
router.post("/request-reset", requestPasswordReset);
router.post("/reset-password/:token", resetPassword);

module.exports=router;