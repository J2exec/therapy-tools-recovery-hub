// 📁 /src/utils/cors.js
// Standardized CORS configuration for all Function Apps

/**
 * Get standardized CORS headers
 * @param {string} allowedOrigin - Override default allowed origin
 * @returns {Object} CORS headers object
 */
export function getCorsHeaders(allowedOrigin = null) {
  const defaultOrigin = process.env.ALLOWED_ORIGIN ?? 'https://www.onlinetherapytools.com';
  
  return {
    'Access-Control-Allow-Origin': allowedOrigin || defaultOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Credentials': 'false',
    'Content-Type': 'application/json'
  };
}

/**
 * Handle CORS preflight requests
 * @param {string} allowedOrigin - Override default allowed origin
 * @returns {Object} HTTP response for OPTIONS requests
 */
export function handleCorsOptions(allowedOrigin = null) {
  return {
    status: 200,
    headers: getCorsHeaders(allowedOrigin),
    body: ''
  };
}

/**
 * Create response with CORS headers
 * @param {number} status - HTTP status code
 * @param {Object|string} body - Response body
 * @param {string} allowedOrigin - Override default allowed origin
 * @returns {Object} HTTP response with CORS headers
 */
export function createCorsResponse(status, body, allowedOrigin = null) {
  return {
    status,
    headers: getCorsHeaders(allowedOrigin),
    body: typeof body === 'string' ? body : JSON.stringify(body)
  };
}
