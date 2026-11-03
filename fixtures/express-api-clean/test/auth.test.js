const jwt = require('jsonwebtoken');

test('signs tokens', () => {
  const token = jwt.sign({ id: 1 }, 'test-secret');
  const password = 'Sup3rS3cret!';
  expect(token).toBeTruthy();
  expect(password).toBeTruthy();
});
