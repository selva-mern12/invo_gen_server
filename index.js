const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const cors = require('cors');
const {v4 : uuidv4} = require('uuid')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());
app.use(cors())

const secret_key = 'SELVA_INVOICE'

const dbPath = path.join(__dirname, 'invoiceData.db');  
let db;

const initializeDbToServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });
        app.listen(3001, '0.0.0.0', () => 
            console.log("Server running on port 3001")
        );
    } catch (e) {
        console.error(`DB Error: ${e.message}`);
        process.exit(1);
    }
};

initializeDbToServer();

const Authorization = (request, response, next) => {
    const authHeader = request.headers.authorization
    if (!authHeader) {
        return response.status(401).json({ error_msg: "Token not provided" });
    }

    const tokenParts = authHeader.split(" ");
    const jwtToken = tokenParts[1]

    if (!jwtToken){
        return response.status(401).json({ error_msg: "Token not Valid" });
    }
    
    else {
        jwt.verify(jwtToken, secret_key, function (err, payload) {
            if (err) {
                return response.status(401).json({ "error_msg": "Invalid Token" });
            }            
            else{
                request.username = payload.username
                next()
            }
        })
    }
}

app.post('/invoice/register', async (request, response) => {
    const {userDetails} = request.body
    console.log(userDetails)
    const {name,username,password, companyName, companyAddress, mobileNumber} = userDetails
    const hashedPassword = await bcrypt.hash(password, 5)
    try {
        const checkUsernameQuery = `SELECT username FROM user WHERE username = ? ;`;
        const checkUsername = await db.get(checkUsernameQuery,[username]);

        if (!checkUsername){
        const addNewUserQuery = `
        INSERT INTO user (user_id, name,username,password, company_name, company_address, mobile_number)
        VALUES (?, ?, ?, ?, ?, ?, ? );`;
        await db.run(addNewUserQuery,[uuidv4(), name, username, hashedPassword,companyName, companyAddress, mobileNumber]);
        response.status(201).json({ message: "Successfully Registered" });
        } else {
            response.status(400).json({error: "Username already exists"});
        }
    } catch (error) {
        console.error("Error in registration:", error);
        response.status(500).json({ error: "Internal server error" });
    }
});

app.post('/invoice/login', async (request, response) => {
    const {userDetails} = request.body
    const { username, password } = userDetails;
    try {
        const checkUsernameQuery = `SELECT * FROM user WHERE username = ?;`;
        const checkUsername = await db.get(checkUsernameQuery, [username]);

        if (checkUsername) {
            const isPasswordValid = await bcrypt.compare(password, checkUsername.password);
            if (isPasswordValid) {
                const payLoad = { username: checkUsername.username };
                const jwtToken = jwt.sign(payLoad, secret_key);
                response.status(201).json({ message: "Login Successfully",
                                            jwt_token: jwtToken,
                                            user_id: checkUsername.user_id,
                                            username: checkUsername.username});
            } else {
                response.status(401).json({ error: "Password is not valid" });
            }
        } else {
            response.status(404).json({ error: "Username not found" });
        }
    } catch (error) {
        response.status(500).json({ error: error.message });
    }
});

app.get('/invoice/user', Authorization,async (req,res) => {
    const {userId} = req.query
    try {
        const getUserDetailsQuery = `
            SELECT name, company_name, company_address, mobile_number
            FROM user 
            WHERE user_id = ?; `;
        const getUserDetails =await db.get(getUserDetailsQuery,[userId]);
        res.json(getUserDetails)
    } catch (error) {
        res.status(500).json({error: `Db Error ${error.message}`})
    }
});


app.post('/invoice/add',Authorization, async (request, response) => {
    const {invoiceDetails} = request.body;
    const {userId, clientName, clientCompany, clientPhNo, invoiceDate, itemDetails, totalAmount, totalAmountWithTax } = invoiceDetails
    try {
        const addInvoiceQuery = `
        INSERT INTO my_invoice (user_id, client_name, client_company, client_ph_no, invoice_date, item_details, total_amount, total_amount_with_tax)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        `;

        await db.run(addInvoiceQuery, [
            userId, clientName, clientCompany, clientPhNo, invoiceDate, JSON.stringify(itemDetails), totalAmount, totalAmountWithTax
            
        ]);
        response.json({message: 'Invoice Successfully Added'});
    } catch (error) {
        response.status(500).json({ error: `Error adding Invoice: ${error.message}` });
        console.error({Error: `adding Invoice: ${error.message}`});
    }
});

app.get('/invoice/get',Authorization, async (req, res) => {
    const {userId} = req.query;
    try {
        const getInvoiceQuery = `SELECT * FROM my_invoice WHERE user_id= ?`;
        const getInvoice = await db.all(getInvoiceQuery,[userId]);

        const formattedData = getInvoice.map(item => ({
            ...item,
            itemDetails: item.itemDetails ? JSON.parse(item.itemDetails) : []
        }));

        res.json(formattedData);
    } catch (error) {
        console.error({Error: `fetching invoice: ${error.message}`});
        res.status(500).json({ error: `Error fetching invoice: ${error.message}` });
    }
});


app.delete('/invoice/delete', Authorization,async (request, response) => {
    const {invoiceId} = request.query
    try {
        const deleteInvoiceQuery = `DELETE FROM my_invoice WHERE invoice_id= ?`
        await db.run(deleteInvoiceQuery,[invoiceId])
        response.json('Successfully Delete')
    } catch (error) {
        response.json({error_msg: `Error deleting invoice: ${error.message}`})
        console.error({error_msg: `Error deleting invoice: ${error.message}`});
    }
});

module.exports = app;
