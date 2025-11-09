const request = require('supertest');
const app = require('../../src/app');

describe('App - Root Endpoint', () => {
  test('GET / returns ok status', async () => {
    const res = await request(app).get('/');
    
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });
});
