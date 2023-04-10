use admin
db.createUser(
  {
    user: "vfsigner",
    pwd: "vfsigner",
    roles: [ { role: "dbOwner", db: "vfsimplesigning" },
            { role: "readWrite", db: "vfsimplesigning" }
    ]
  }
)

use vfsimplesigning
db.createUser(
  {
    user: "vfsigner",
    pwd: "vfsigner",
    roles: [ { role: "dbOwner", db: "vfsimplesigning" },
            { role: "readWrite", db: "vfsimplesigning" }
    ]
  }
)
