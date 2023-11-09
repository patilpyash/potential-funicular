// app.js
const express = require('express');
const { swaggerUi, swaggerSpec } = require('./swagger');
const userRoutes = require('./userRoutes');

const app = express();
app.use(express.json());
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use('/', userRoutes);

app.listen(3000, () => {
    console.log('Server started on port 3000');
});
