db.createUser({
  user: 'root',
  pwd: 'r0ot@31',
  roles: [
    {
      role: 'readWrite',
      db: 'vfsimplesigning'
    }
  ]
});