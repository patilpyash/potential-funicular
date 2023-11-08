const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const swaggerOptions = {
    swaggerDefinition: {
      openapi: '3.0.0',
      info: {
        title: 'Your API',
        version: '1.0.0',
        description: 'API documentation',
      },
    //   ...
    //   components: {
    //     securitySchemes: {
    //       BearerAuth: {
    //         type: 'http',
    //         scheme: 'bearer',
    //         bearerFormat: 'JWT',
    //       },
    //     },
    //   },
    //   ...
    },
    apis: ['./index.js'], // Path to your API routes
  };
  

const swaggerSpec = swaggerJsdoc(swaggerOptions);

module.exports = { swaggerSpec, swaggerUi };
