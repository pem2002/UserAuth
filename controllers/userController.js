const db =require('../Config/db');
exports.getDashboard = (req, res)=>{
    res.render('user/dashboard',{message: null})
}
exports.getAllFoods =async (req, res)=>{
    try {
        const foods = await db.query('SELECT * FROM food_items ORDER BY created_at DESC');
        res.render ('user/foods',{foods});
    } catch (error){
        console.error('Error fetching food items:',error);
        res.status(500).send ('Server Error')
    }
}