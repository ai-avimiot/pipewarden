const { fetchData } = require('./index');

test('fetchData is a function', () => {
  expect(typeof fetchData).toBe('function');
});
